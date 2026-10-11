module RealTree.Authzn.Tests.ConcurrencyTests

open System
open System.Threading
open System.Threading.Tasks
open Xunit
open RealTree.Authzn
open RealTree.Authzn.Tests.Helpers

let private count = 2000

[<Fact>]
let ``InMemoryAssignmentStore keeps every assignment added while readers enumerate`` () =
    let store = InMemoryAssignmentStore()
    let reader = store :> IAssignmentStore

    let readers =
        Task.Run(fun () ->
            for _ in 1..count do
                reader.GetAssignmentsForPrincipalAsync(testPrincipal, CancellationToken.None).Result |> List.length |> ignore)

    Parallel.For(0, count, (fun i -> store.Add(Assignment.create testPrincipal (RoleId $"role-{i}"))))
    |> ignore

    readers.Wait()

    let stored = reader.GetAssignmentsForPrincipalAsync(testPrincipal, CancellationToken.None).Result
    Assert.Equal(count, stored |> List.map (fun a -> a.Role) |> List.distinct |> List.length)

[<Fact>]
let ``InMemoryRoleStore keeps every role added while readers look roles up`` () =
    let store = InMemoryRoleStore()
    let reader = store :> IRoleStore

    let readers =
        Task.Run(fun () ->
            for i in 1..count do
                reader.GetRoleAsync(RoleId $"role-{i % 100}", CancellationToken.None).Result |> ignore)

    Parallel.For(0, count, (fun i -> store.Add({ Id = RoleId $"role-{i}"; Name = $"Role {i}"; Grants = [] })))
    |> ignore

    readers.Wait()

    for i in 0 .. count - 1 do
        Assert.True(reader.GetRoleAsync(RoleId $"role-{i}", CancellationToken.None).Result.IsSome)

[<Fact>]
let ``InMemoryGrantStore keeps every revocation when grants of one role are revoked concurrently`` () =
    let grants =
        [ for i in 1..200 ->
              { Permission = PermissionPattern.parse $"resource-{i}:read"
                Scope = Map.empty
                Condition = None
                Metadata = GrantMetadata.empty } ]

    let roleStore = InMemoryRoleStore()
    roleStore.Add({ Id = RoleId "r"; Name = "R"; Grants = grants })
    let grantStore = InMemoryGrantStore(roleStore) :> IGrantStore
    let at = DateTimeOffset.UtcNow

    Parallel.ForEach(
        grants,
        fun grant -> grantStore.RevokeGrantAsync(RoleId "r", GrantKey.forGrant grant, PrincipalId "admin", at, CancellationToken.None).Wait()
    )
    |> ignore

    let stored = (roleStore :> IRoleStore).GetRoleAsync(RoleId "r", CancellationToken.None).Result.Value
    Assert.All(stored.Grants, fun g -> Assert.Equal(Some at, g.Metadata.RevokedAt))
