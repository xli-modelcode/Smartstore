using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Autofac;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using Smartstore.Caching;
using Smartstore.Collections;
using Smartstore.Core.Data;
using Smartstore.Core.Identity;
using Smartstore.Core.Identity.Rules;
using Smartstore.Core.Rules;
using Smartstore.Core.Rules.Filters;
using Smartstore.Core.Security;
using Smartstore.Data;
using Smartstore.Data.Providers;
using Smartstore.Engine;
using Smartstore.Engine.Modularity;
using Smartstore.IO;
using Smartstore.Scheduling;
using Smartstore.Test.Common;
using Smartstore.Threading;
using Smartstore.Utilities;

namespace Smartstore.Core.Tests.Platform.Identity.Rules;

/// <summary>
/// Regression tests for <see cref="TargetGroupEvaluatorTask"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="TargetGroupEvaluatorTask.Run"/> unconditionally calls
/// <c>_db.CustomerRoleMappings....ExecuteDeleteAsync(cancelToken)</c> before doing anything else.
/// EF Core's InMemory provider does not support <c>ExecuteDelete</c>/<c>ExecuteUpdate</c> at all
/// (see https://github.com/dotnet/efcore/issues/29376, closed as "not planned") - every call throws
/// <see cref="InvalidOperationException"/> regardless of the query. <see cref="TestDbFactory"/> (used
/// by <see cref="ServiceTestBase"/> and most other tests in this project) is backed by the InMemory
/// provider and is therefore unusable here.
/// </para>
/// <para>
/// Instead, this fixture backs <see cref="SmartDbContext"/> with EF Core's relational Sqlite provider
/// running against an open <c>:memory:</c> connection (<see cref="TestSqliteDbFactory"/>). Sqlite fully
/// supports <c>ExecuteDelete</c>/<c>ExecuteUpdate</c> and - unlike a plain LINQ-to-Objects queryable -
/// its query provider implements <c>IAsyncQueryProvider</c>, which <see cref="Smartstore.Data.FastPager{T}"/>
/// requires because it calls EF Core's <c>IQueryable.ToListAsync()</c> internally. The Sqlite connection
/// must stay open for the lifetime of the context, because the in-memory database is destroyed the
/// moment the connection closes.
/// </para>
/// <para>
/// <c>UseDbFactory(...)</c> constructs a <see cref="DbFactoryOptionsExtension"/>, whose constructor reads
/// <c>EngineContext.Current.Application.Services</c>. To keep this fixture independently runnable without
/// pulling in <see cref="ServiceTestBase"/>'s full host/engine bootstrap, <see cref="SetUp"/> installs a
/// minimal <see cref="TestEngine"/>/<see cref="MinimalApplicationContext"/> pair for the duration of each
/// test and <see cref="TearDown"/> restores whatever engine was previously current.
/// </para>
/// <para>
/// <see cref="MinimalApplicationContext"/> throws <see cref="NotImplementedException"/> for every member
/// it doesn't need, including <see cref="IApplicationContext.IsWebHost"/>. <see cref="CommonHelper.IsHosted"/>
/// caches <c>EngineContext.Current.Application.IsWebHost</c> once per process the first time anything reads
/// it, so if this fixture ran before any <see cref="CommonHelper.IsHosted"/> read elsewhere, that lazy
/// evaluation would hit <see cref="MinimalApplicationContext"/> and throw. <see cref="SetUp"/> therefore
/// sets <see cref="CommonHelper.IsHosted"/> (and <see cref="CommonHelper.IsDevEnvironment"/>) explicitly,
/// exactly as <see cref="ServiceTestBase"/> does, so that lazy evaluation never happens.
/// </para>
/// </remarks>
[TestFixture]
public class TargetGroupEvaluatorTaskTests
{
    private const string CustomerRoleIdsParameterName = "CustomerRoleIds";

    private SqliteConnection _connection;
    private SmartDbContext _db;
    private IEngine _previousEngine;

    private Mock<ICacheManager> _cacheMock;
    private Mock<IRuleService> _ruleServiceMock;
    private Mock<ITargetGroupService> _targetGroupServiceMock;
    private Mock<IRuleProviderFactory> _ruleProviderFactoryMock;

    [SetUp]
    public void SetUp()
    {
        // UseDbFactory(...) below constructs a DbFactoryOptionsExtension, whose constructor reads
        // EngineContext.Current.Application.Services (an Autofac scope) to look up SmartConfiguration.
        // This fixture deliberately avoids ServiceTestBase's full engine/host bootstrap (see class
        // remarks). TestEngine.Start(...) would trigger EngineStarter<T>'s module-loading machinery,
        // so the Application property is set directly instead - and whatever engine was previously
        // current is restored in TearDown, so this doesn't leak state into other fixtures.
        _previousEngine = EngineContext.Current;
        EngineContext.Replace(new TestEngine
        {
            Application = new MinimalApplicationContext(new ContainerBuilder().Build())
        });

        // MinimalApplicationContext.IsWebHost throws, so force CommonHelper's lazy-cached flags to a
        // known value up front - exactly as ServiceTestBase does - instead of letting something read
        // CommonHelper.IsHosted for the first time against this fixture's minimal engine and throw.
        CommonHelper.IsHosted = false;
        CommonHelper.IsDevEnvironment = false;

        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        DataSettings.Instance = new DataSettings
        {
            AppVersion = SmartstoreVersion.Version,
            ConnectionString = "Test",
            TenantName = "Default",
            TenantRoot = null,
            DbFactory = new TestSqliteDbFactory(_connection)
        };

        DataSettings.SetTestMode(true);

        var optionsBuilder = new DbContextOptionsBuilder<SmartDbContext>()
            .UseDbFactory(factoryBuilder =>
            {
                factoryBuilder.AddModelAssemblies(new[]
                {
                    typeof(SmartDbContext).Assembly
                });
            });

        _db = new SmartDbContext((DbContextOptions<SmartDbContext>)optionsBuilder.Options);
        _db.Database.EnsureCreated();

        _cacheMock = new Mock<ICacheManager>();
        _ruleServiceMock = new Mock<IRuleService>();
        _targetGroupServiceMock = new Mock<ITargetGroupService>();

        _ruleProviderFactoryMock = new Mock<IRuleProviderFactory>();
        _ruleProviderFactoryMock
            .Setup(x => x.GetProvider(RuleScope.Customer, It.IsAny<object>()))
            .Returns(_targetGroupServiceMock.Object);
    }

    [TearDown]
    public void TearDown()
    {
        _db?.Dispose();
        _connection?.Dispose();

        DataSettings.Reload();

        EngineContext.Replace(_previousEngine);
    }

    #region Scenario 1: CustomerRoleIds scoping

    [Test]
    public async Task Run_respects_CustomerRoleIds_parameter_and_leaves_other_roles_untouched()
    {
        var (roleA, ruleSetA) = CreateRoleWithRuleSet("RoleA");
        var (roleB, ruleSetB) = CreateRoleWithRuleSet("RoleB");

        var customerA1 = new Customer();
        var customerA2 = new Customer();
        var customerB1 = new Customer();
        _db.Customers.AddRange(customerA1, customerA2, customerB1);
        _db.SaveChanges();

        // Pre-existing system mappings for both roles.
        _db.CustomerRoleMappings.Add(new CustomerRoleMapping { CustomerId = customerA1.Id, CustomerRoleId = roleA.Id, IsSystemMapping = true });
        _db.CustomerRoleMappings.Add(new CustomerRoleMapping { CustomerId = customerB1.Id, CustomerRoleId = roleB.Id, IsSystemMapping = true });
        _db.SaveChanges();

        // Only role A's rule set may ever be evaluated; it recomputes to customer A2.
        SetupRuleEvaluation(ruleSetA, customerA2.Id);

        var task = CreateTask();
        var (ctx, _) = CreateExecutionContext(new Dictionary<string, string>
        {
            [CustomerRoleIdsParameterName] = roleA.Id.ToString()
        });

        await task.Run(ctx);

        var roleAMappings = _db.CustomerRoleMappings.Where(x => x.CustomerRoleId == roleA.Id).ToList();
        roleAMappings.Count.ShouldEqual(1);
        roleAMappings[0].CustomerId.ShouldEqual(customerA2.Id);

        // Role B's original mapping must be untouched: not deleted, not duplicated.
        var roleBMappings = _db.CustomerRoleMappings.Where(x => x.CustomerRoleId == roleB.Id).ToList();
        roleBMappings.Count.ShouldEqual(1);
        roleBMappings[0].CustomerId.ShouldEqual(customerB1.Id);

        _ruleServiceMock.Verify(
            x => x.CreateExpressionGroupAsync(It.Is<RuleSetEntity>(rs => rs.Id == ruleSetB.Id), It.IsAny<IRuleVisitor>(), It.IsAny<bool>()),
            Times.Never);
    }

    #endregion

    #region Scenario 2: role / rule set eligibility filtering

    [Test]
    public async Task Run_excludes_inactive_roles_and_roles_without_an_active_rule_set()
    {
        // Active == false, despite having an active rule set: must be excluded.
        var (inactiveRole, inactiveRoleRuleSet) = CreateRoleWithRuleSet("InactiveRole", roleActive: false, ruleSetActive: true);

        // Active == true, but its only rule set is not active: must be excluded too.
        var (roleWithoutActiveRuleSet, itsInactiveRuleSet) = CreateRoleWithRuleSet("RoleWithoutActiveRuleSet", roleActive: true, ruleSetActive: false);

        // Control role: active, with an active rule set. Proves the filter isn't excluding everything.
        var (eligibleRole, eligibleRuleSet) = CreateRoleWithRuleSet("EligibleRole", roleActive: true, ruleSetActive: true);

        var customer = new Customer();
        _db.Customers.Add(customer);
        _db.SaveChanges();

        SetupRuleEvaluation(eligibleRuleSet, customer.Id);

        var task = CreateTask();
        var (ctx, _) = CreateExecutionContext();

        await task.Run(ctx);

        _db.CustomerRoleMappings.Any(x => x.CustomerRoleId == inactiveRole.Id).ShouldBeFalse();
        _db.CustomerRoleMappings.Any(x => x.CustomerRoleId == roleWithoutActiveRuleSet.Id).ShouldBeFalse();

        var eligibleMappings = _db.CustomerRoleMappings.Where(x => x.CustomerRoleId == eligibleRole.Id).ToList();
        eligibleMappings.Count.ShouldEqual(1);
        eligibleMappings[0].CustomerId.ShouldEqual(customer.Id);

        // The excluded roles' rule sets must never reach the rule evaluation pipeline.
        _ruleServiceMock.Verify(
            x => x.CreateExpressionGroupAsync(It.Is<RuleSetEntity>(rs => rs.Id == inactiveRoleRuleSet.Id), It.IsAny<IRuleVisitor>(), It.IsAny<bool>()),
            Times.Never);
        _ruleServiceMock.Verify(
            x => x.CreateExpressionGroupAsync(It.Is<RuleSetEntity>(rs => rs.Id == itsInactiveRuleSet.Id), It.IsAny<IRuleVisitor>(), It.IsAny<bool>()),
            Times.Never);
    }

    #endregion

    #region Scenario 3: paging / chunking beyond 500 rows

    [Test]
    public async Task Run_adds_mappings_for_more_than_500_matching_customers()
    {
        const int customerCount = 750;

        var (role, ruleSet) = CreateRoleWithRuleSet("BigRole");

        var customers = Enumerable.Range(0, customerCount).Select(_ => new Customer()).ToList();
        _db.Customers.AddRange(customers);
        _db.SaveChanges();

        var customerIds = customers.Select(x => x.Id).ToArray();

        SetupRuleEvaluation(ruleSet, customerIds);

        var task = CreateTask();
        var (ctx, _) = CreateExecutionContext();

        await task.Run(ctx);

        var mappedCustomerIds = _db.CustomerRoleMappings
            .Where(x => x.CustomerRoleId == role.Id)
            .Select(x => x.CustomerId)
            .OrderBy(x => x)
            .ToList();

        mappedCustomerIds.Count.ShouldEqual(customerCount);
        mappedCustomerIds.ShouldSequenceEqual(customerIds.OrderBy(x => x));
    }

    #endregion

    #region Scenario 4: cache invalidation

    [Test]
    public async Task Run_invalidates_acl_cache_when_mappings_were_added()
    {
        var (role, ruleSet) = CreateRoleWithRuleSet("RoleWithAddedMapping");

        var customer = new Customer();
        _db.Customers.Add(customer);
        _db.SaveChanges();

        SetupRuleEvaluation(ruleSet, customer.Id);

        var task = CreateTask();
        var (ctx, _) = CreateExecutionContext();

        await task.Run(ctx);

        _cacheMock.Verify(x => x.RemoveByPatternAsync(AclService.ACL_SEGMENT_PATTERN), Times.Once);
    }

    [Test]
    public async Task Run_invalidates_acl_cache_when_mappings_were_deleted_only()
    {
        // Rule set produces zero customers, so nothing is added. But a stale system mapping exists
        // and will be deleted up-front, so numDeleted > 0 while numAdded stays 0.
        var (role, ruleSet) = CreateRoleWithRuleSet("RoleWithDeletedMapping");

        var customer = new Customer();
        _db.Customers.Add(customer);
        _db.SaveChanges();

        _db.CustomerRoleMappings.Add(new CustomerRoleMapping { CustomerId = customer.Id, CustomerRoleId = role.Id, IsSystemMapping = true });
        _db.SaveChanges();

        SetupRuleEvaluation(ruleSet);

        var task = CreateTask();
        var (ctx, _) = CreateExecutionContext();

        await task.Run(ctx);

        _db.CustomerRoleMappings.Any(x => x.CustomerRoleId == role.Id).ShouldBeFalse();
        _cacheMock.Verify(x => x.RemoveByPatternAsync(AclService.ACL_SEGMENT_PATTERN), Times.Once);
    }

    [Test]
    public async Task Run_does_not_invalidate_acl_cache_when_nothing_changed()
    {
        var (_, ruleSet) = CreateRoleWithRuleSet("RoleWithNoChanges");

        SetupRuleEvaluation(ruleSet);

        var task = CreateTask();
        var (ctx, _) = CreateExecutionContext();

        await task.Run(ctx);

        _cacheMock.Verify(x => x.RemoveByPatternAsync(It.IsAny<string>()), Times.Never);
    }

    #endregion

    #region Scenario 5: mid-run cancellation

    [Test]
    public async Task Run_stops_without_completing_all_roles_when_cancelled_mid_run()
    {
        var (roleX, ruleSetX) = CreateRoleWithRuleSet("RoleX");
        var (roleY, ruleSetY) = CreateRoleWithRuleSet("RoleY");

        var customerX = new Customer();
        var customerY = new Customer();
        _db.Customers.AddRange(customerX, customerY);
        _db.SaveChanges();

        SetupRuleEvaluation(ruleSetX, customerX.Id);
        SetupRuleEvaluation(ruleSetY, customerY.Id);

        var cts = new CancellationTokenSource();
        var (ctx, taskStoreMock) = CreateExecutionContext();

        // Roles are processed one after another. Cancel as soon as progress is reported for the
        // second role - i.e. right after the first role has been fully committed, but before the
        // second role's rule sets are evaluated. This exercises the task's own graceful cancellation
        // checks rather than aborting the initial delete/query with an already-cancelled token.
        var progressReports = 0;
        taskStoreMock
            .Setup(x => x.UpdateExecutionInfoAsync(It.IsAny<TaskExecutionInfo>()))
            .Callback(() =>
            {
                progressReports++;
                if (progressReports == 2)
                {
                    cts.Cancel();
                }
            })
            .Returns(Task.CompletedTask);

        var task = CreateTask();

        await task.Run(ctx, cts.Token);

        var allMappings = _db.CustomerRoleMappings.ToList();

        // Fewer mappings than the full expected set (2): the run was cut short.
        allMappings.Count.ShouldEqual(1);

        // Exactly one role's rule set pipeline ran to completion; the other role was never reached
        // because the task returned as soon as cancellation was observed between the two roles.
        var createExpressionGroupInvocations = _ruleServiceMock.Invocations.Count(i => i.Method.Name == nameof(IRuleService.CreateExpressionGroupAsync));
        createExpressionGroupInvocations.ShouldEqual(1);

        var processFilterInvocations = _targetGroupServiceMock.Invocations.Count(i => i.Method.Name == nameof(ITargetGroupService.ProcessFilter));
        processFilterInvocations.ShouldEqual(1);
    }

    #endregion

    #region Helpers

    private TargetGroupEvaluatorTask CreateTask()
        => new(_db, _cacheMock.Object, _ruleServiceMock.Object, _ruleProviderFactoryMock.Object);

    private static (TaskExecutionContext Context, Mock<ITaskStore> TaskStoreMock) CreateExecutionContext(IDictionary<string, string> parameters = null)
    {
        var taskStoreMock = new Mock<ITaskStore>();
        var asyncStateMock = new Mock<IAsyncState>();
        var componentContextMock = new Mock<IComponentContext>();
        var httpContext = new DefaultHttpContext();

        var executionInfo = new TaskExecutionInfo
        {
            // TaskExecutionInfo.Clone() (invoked by the TaskExecutionContext constructor) calls
            // Task.Clone(). Task's getter falls back to the lazy loader, which is a no-op
            // NullLazyLoader outside of a bootstrapped DI engine, so Task must be assigned explicitly
            // here to avoid a NullReferenceException.
            Task = new TaskDescriptor
            {
                Name = "TargetGroupEvaluatorTask",
                Type = typeof(TargetGroupEvaluatorTask).AssemblyQualifiedName
            }
        };

        var context = new TaskExecutionContext(
            taskStoreMock.Object,
            asyncStateMock.Object,
            httpContext,
            componentContextMock.Object,
            executionInfo,
            parameters);

        return (context, taskStoreMock);
    }

    private (CustomerRole Role, RuleSetEntity RuleSet) CreateRoleWithRuleSet(string systemName, bool roleActive = true, bool ruleSetActive = true)
    {
        var ruleSet = new RuleSetEntity
        {
            Name = systemName + "-RuleSet",
            IsActive = ruleSetActive,
            Scope = RuleScope.Customer
        };

        var role = new CustomerRole
        {
            Name = systemName,
            SystemName = systemName,
            Active = roleActive
        };

        role.RuleSets.Add(ruleSet);

        _db.CustomerRoles.Add(role);
        _db.SaveChanges();

        return (role, ruleSet);
    }

    /// <summary>
    /// Stubs the rule-evaluation pipeline for <paramref name="ruleSet"/>: <see cref="IRuleService.CreateExpressionGroupAsync"/>
    /// resolves to a fresh <see cref="FilterExpressionGroup"/> keyed to <paramref name="ruleSet"/>'s id, and
    /// <see cref="ITargetGroupService.ProcessFilter"/> resolves to <see cref="CreateFilterResult"/> for that
    /// same group instance, containing <paramref name="customerIds"/>.
    /// </summary>
    private void SetupRuleEvaluation(RuleSetEntity ruleSet, params int[] customerIds)
    {
        var group = new FilterExpressionGroup(typeof(Customer));
        _ruleServiceMock
            .Setup(x => x.CreateExpressionGroupAsync(It.Is<RuleSetEntity>(rs => rs.Id == ruleSet.Id), It.IsAny<IRuleVisitor>()))
            .ReturnsAsync(group);
        _targetGroupServiceMock
            .Setup(x => x.ProcessFilter(It.Is<FilterExpression[]>(f => f.Length == 1 && ReferenceEquals(f[0], group)), LogicalRuleOperator.And, 0, 500))
            .Returns(CreateFilterResult(customerIds));
    }

    /// <summary>
    /// Builds an <see cref="IPagedList{T}"/> whose <c>SourceQuery</c> is backed by the real,
    /// Sqlite-backed <see cref="SmartDbContext"/> rather than an in-memory LINQ-to-Objects queryable.
    /// This matters because <see cref="Smartstore.Data.FastPager{T}"/> calls EF Core's
    /// <c>IQueryable.ToListAsync()</c> internally, which throws unless the query's provider
    /// implements <c>IAsyncQueryProvider</c> - something a plain <c>List&lt;T&gt;.AsQueryable()</c>
    /// does not.
    /// </summary>
    private IPagedList<Customer> CreateFilterResult(params int[] customerIds)
    {
        return _db.Customers.Where(x => customerIds.Contains(x.Id)).ToPagedList(0, 500);
    }

    /// <summary>
    /// Minimal <see cref="DbFactory"/> that configures <see cref="SmartDbContext"/> against an open
    /// Sqlite <c>:memory:</c> connection, mirroring <see cref="TestDbFactory"/>'s shape. The InMemory
    /// provider used by <see cref="TestDbFactory"/> cannot execute <c>ExecuteDelete</c>/<c>ExecuteUpdate</c>
    /// at all, which <see cref="TargetGroupEvaluatorTask.Run"/> relies on; Sqlite can.
    /// </summary>
    private sealed class TestSqliteDbFactory : DbFactory
    {
        private readonly DbConnection _connection;

        public TestSqliteDbFactory(DbConnection connection)
        {
            _connection = connection;
        }

        public override DbSystemType DbSystem { get; } = DbSystemType.SQLite;

        public override DbConnectionStringBuilder CreateConnectionStringBuilder(string connectionString)
            => throw new NotImplementedException();

        public override DbConnectionStringBuilder CreateConnectionStringBuilder(
            string server,
            string database,
            string userName,
            string password)
            => throw new NotImplementedException();

        public override DataProvider CreateDataProvider(DatabaseFacade database)
            => new TestDataProvider(database);

        public override TContext CreateDbContext<TContext>(string connectionString, int? commandTimeout = null)
        {
            var optionsBuilder = new DbContextOptionsBuilder<TContext>().UseSqlite(_connection);
            return (TContext)Activator.CreateInstance(typeof(TContext), new object[] { optionsBuilder.Options });
        }

        public override DbContextOptionsBuilder ConfigureDbContext(DbContextOptionsBuilder builder, string connectionString)
            => builder.UseSqlite(_connection);
    }

    /// <summary>
    /// Minimal <see cref="IApplicationContext"/> whose only purpose is to give
    /// <see cref="DbFactoryOptionsExtension"/>'s constructor a working <c>Services</c> scope to resolve
    /// against. Autofac's <c>ResolveOptional&lt;TService&gt;()</c> tolerates nothing being registered, so
    /// an empty Autofac scope is sufficient. Every other member is unused by this fixture.
    /// </summary>
    private sealed class MinimalApplicationContext : IApplicationContext
    {
        public MinimalApplicationContext(ILifetimeScope services)
        {
            Services = services;
        }

        public ILifetimeScope Services { get; }

        public IHostEnvironment HostEnvironment => throw new NotImplementedException();
        public IConfiguration Configuration => throw new NotImplementedException();
        public ILogger Logger => throw new NotImplementedException();
        public SmartConfiguration AppConfiguration => throw new NotImplementedException();
        public IModuleCatalog ModuleCatalog { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ITypeScanner TypeScanner { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public bool IsInstalled => throw new NotImplementedException();
        public bool IsWebHost => throw new NotImplementedException();
        public RuntimeInfo RuntimeInfo => throw new NotImplementedException();
        public IOSIdentity OSIdentity => throw new NotImplementedException();
        public IFileSystem ContentRoot => throw new NotImplementedException();
        public IFileSystem WebRoot => throw new NotImplementedException();
        public IFileSystem ThemesRoot => throw new NotImplementedException();
        public IFileSystem ModulesRoot => throw new NotImplementedException();
        public IFileSystem AppDataRoot => throw new NotImplementedException();
        public IFileSystem TenantRoot => throw new NotImplementedException();

        public IDirectory GetTempDirectory(string subDirectory = null) => throw new NotImplementedException();
        public IDirectory GetTenantTempDirectory(string subDirectory = null) => throw new NotImplementedException();
    }

    #endregion
}
