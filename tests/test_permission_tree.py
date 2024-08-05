from unittest import TestCase

from ommnia_permission_tree import PermissionTree


class PermissionTreeTest(TestCase):
    def test_simple(self) -> None:
        tree: PermissionTree = PermissionTree({})

        tree.grant_many_from_strings(
            [
                "authentication.users.create",
                "authentication.users.read",
                "authentication.groups",
                "authentication.permissions.read",
            ]
        )

        self.assertTrue(tree.check("authentication.users.create"))
        self.assertTrue(tree.check("authentication.users.read"))
        self.assertFalse(tree.check("authentication.users.update"))
        self.assertTrue(tree.check("authentication.groups"))
        self.assertTrue(tree.check("authentication.groups.create"))
        self.assertTrue(tree.check("authentication.groups.read"))
        self.assertFalse(tree.check("authentication.permissions.delete"))

    def test_revoke(self) -> None:
        tree: PermissionTree = PermissionTree({})

        tree.grant_many_from_strings(
            [
                "authentication.users.create",
                "authentication.users.read",
                "authentication.groups",
                "authentication.permissions.read",
            ]
        )

        self.assertTrue(tree.revoke("authentication.users.read"))

        self.assertTrue(tree.check("authentication.users.create"))
        self.assertFalse(tree.check("authentication.users.read"))
        self.assertFalse(tree.check("authentication.users.update"))
        self.assertTrue(tree.check("authentication.groups"))
        self.assertTrue(tree.check("authentication.groups.create"))
        self.assertTrue(tree.check("authentication.groups.read"))
        self.assertFalse(tree.check("authentication.permissions.delete"))

    def test_merge(self) -> None:
        first_tree: PermissionTree = PermissionTree({})
        first_tree.grant_many_from_strings(
            [
                "auth.users.create",
                "auth.users.update",
                "auth.groups.read",
                "auth.permissions",
            ]
        )

        second_tree: PermissionTree = PermissionTree({})
        second_tree.grant_many_from_strings(
            [
                "auth.permissions.create",
                "auth.permissions.update",
                "auth.groups.create",
                "auth.users",
            ]
        )

        union = first_tree.union(second_tree)

        print(union)

    def test_intersect(self) -> None:
        a: PermissionTree = PermissionTree({})
        a.grant_many_from_strings(
            ["auth.permissions.create", "auth.permissions.update", "auth.groups.create"]
        )

        b: PermissionTree = PermissionTree({})
        b.grant_many_from_strings(["auth.permissions.create", "auth.groups"])
