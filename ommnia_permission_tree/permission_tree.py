from dataclasses import dataclass, field
from typing import Dict, Generator, Iterable, List, Optional
from more_itertools import peekable


type PermissionTreeData = Dict[str, PermissionTreeData]


@dataclass
class PermissionTree:
    _data: PermissionTreeData = field(default_factory=lambda: {})

    def union(self, other: "PermissionTree") -> "PermissionTree":
        """
        Returns a new PermissionTree that represents the union of the current PermissionTree and another PermissionTree.

        Parameters:
            other (PermissionTree): The PermissionTree to be merged with the current PermissionTree.

        Returns:
            PermissionTree: A new PermissionTree object that contains the merged permissions from both trees.
        """

        def inner_union(
            left: PermissionTreeData, right: PermissionTreeData
        ) -> PermissionTreeData:
            result: PermissionTreeData = {}

            for key in left:
                if key in result and result[key] == {}:
                    continue

                if key not in right:
                    result[key] = left[key]
                    continue

                if right[key] == {}:
                    result[key] = {}
                    continue

                result[key] = inner_union(left[key], right[key])

            for key in right:
                if key in result and result[key] == {}:
                    continue

                if key not in left:
                    result[key] = right[key]
                    continue

                if left[key] == {}:
                    result[key] = {}
                    continue

                result[key] = inner_union(left[key], right[key])

            return result

        return PermissionTree(inner_union(self._data, other._data))

    def check(self, permission: str) -> bool:
        """
        Check if a given permission is present in the permission tree.

        Args:
            permission (str): The permission to check.

        Returns:
            bool: True if the permission is present, False otherwise.
        """

        segments: List[str] = permission.split(".")

        data: PermissionTreeData = self._data

        for segment in segments:
            if segment not in data:
                return data == {}

            data = data[segment]

        return data == {}

    def check_any(self, permissions: Iterable[str]) -> bool:
        """
        Checks if any of the given permissions are granted.

        Args:
            permissions (Iterable[str]): The permissions to check.

        Returns:
            bool: True if any of the permissions are granted, False otherwise.
        """

        for permission in permissions:
            if self.check(permission):
                return True

        return False

    def check_all(self, permissions: Iterable[str]) -> bool:
        """
        Checks if all the given permissions are granted.

        Args:
            permissions (Iterable[str]): A collection of permissions to check.

        Returns:
            bool: True if all permissions are granted, False otherwise.
        """

        for permission in permissions:
            if not self.check(permission):
                return False

        return True

    def grant(self, permission: Iterable[str]) -> None:
        """
        Grants a permission in the permission tree.

        Args:
            permission (Iterable[str]): The permission to be granted.

        Returns:
            None
        """

        segments_iter: peekable[str] = peekable(permission)

        data: PermissionTreeData = self._data

        while True:
            segment: Optional[str] = next(segments_iter, None)
            if segment is None:
                break

            last: bool = segments_iter.peek(None) is None

            # If segment not in data, put it in and assign an empty map.
            if segment not in data:
                data[segment] = {}
                data = data[segment]
                continue

            # If last segment, overrule nested permissions by assigning a map.
            if last:
                data[segment] = {}
                data = data[segment]
                continue

            # If not last segment and already in data, walk into it.
            data = data[segment]

    def grant_from_string(self, permission: str) -> None:
        """
        Grants a permission in the permission tree.

        Args:
            permission (str): The permission to be granted.

        Returns:
            None
        """

        return self.grant(permission.split("."))

    def grant_many_from_strings(self, permissions: Iterable[str]) -> "PermissionTree":
        """
        Grants multiple permissions to the permission tree.

        Args:
            permissions (Iterable[str]): An iterable of permission strings to be granted.

        Returns:
            None
        """

        for permission in permissions:
            self.grant_from_string(permission)

        return self

    def revoke(self, permission: str) -> bool:
        """
        Revoke a permission from the permission tree.

        Args:
            permission (str): The permission to revoke.

        Returns:
            bool: True if the permission was successfully revoked, False otherwise.
        """

        segments: List[str] = permission.split(".")
        data: PermissionTreeData = self._data

        for segment in segments:
            if segment not in data:
                return False

            last: bool = segment == segments[-1]
            if last:
                del data[segment]
                break

            data = data[segment]

        return True

    def revoke_any(self, permissions: Iterable[str]) -> bool:
        """
        Revokes any of the given permissions.

        Args:
            permissions (Iterable[str]): The permissions to revoke.

        Returns:
            bool: True if any of the permissions were successfully revoked, False otherwise.
        """

        for permission in permissions:
            if self.revoke(permission):
                return True

        return False

    def revoke_all(self, permissions: Iterable[str]) -> bool:
        """
        Revokes all the given permissions.

        Args:
            permissions (Iterable[str]): The permissions to revoke.

        Returns:
            bool: True if all permissions were successfully revoked, False otherwise.
        """

        for permission in permissions:
            if not self.revoke(permission):
                return False

        return True

    def names(self) -> Generator[str, None, None]:
        """
        Returns a generator that yields the names of all permissions in the permission tree.

        Yields:
            str: The name of a permission.
        """

        def inner_names(data: PermissionTreeData) -> Generator[str, None, None]:
            for key in data:
                yield key
                yield from inner_names(data[key])

        return inner_names(self._data)

    def contains(self, other: "PermissionTree") -> bool:
        """
        Checks if the current PermissionTree contains all the permissions of another PermissionTree.

        Args:
            other (PermissionTree): The PermissionTree to check against.

        Returns:
            bool: True if the current PermissionTree contains all the permissions of the other PermissionTree, False otherwise.
        """

        def inner_contains(a: PermissionTreeData, b: PermissionTreeData) -> bool:
            for key in b:
                if key not in a:
                    return False

                # If it is an empty dict in a, then always return true, since it
                #  will match all children.
                if a[key] == {}:
                    continue

                # If the B key is empty, and the a key is not empty, then simply
                #  return False since it is not sure if it matches all children.
                if b[key] == {}:
                    return False

                if not inner_contains(a[key], b[key]):
                    return False

            return True

        return inner_contains(self._data, other._data)

    def intersect(self, right: "PermissionTree") -> "PermissionTree":
        """
        Returns a new PermissionTree that represents the intersection of the current PermissionTree and another PermissionTree.

        Parameters:
            right (PermissionTree): The PermissionTree to be intersected with the current PermissionTree.

        Returns:
            PermissionTree: A new PermissionTree object that contains the intersected permissions from both trees.
        """

        def inner_intersect(
            left: PermissionTreeData,
            right: PermissionTreeData,
        ) -> PermissionTreeData:
            result: PermissionTreeData = {}

            for key in left:
                # Ignore keys that are not present in the right side
                if key not in right:
                    continue

                # Copy the entire contents of the right side if the key in the left side is empty
                if left[key] == {}:
                    result[key] = right[key]
                    continue

                # Recurse deeper
                result[key] = inner_intersect(left[key], right[key])

            return result

        return PermissionTree(inner_intersect(self._data, right._data))

    def to_strings(self) -> Generator[str, None, None]:
        """
        Converts the permission tree into a generator of strings.

        Yields:
            str: A string representation of each permission in the tree.
        """

        def inner_to_strings(
            data: PermissionTreeData, segments: List[str]
        ) -> Generator[str, None, None]:
            if data == {} and len(segments) > 0:
                yield ".".join(segments)

            for key in data:
                new_segments: List[str] = [x for x in segments]
                new_segments.append(key)
                yield from inner_to_strings(data[key], new_segments)

        yield from inner_to_strings(self._data, [])
