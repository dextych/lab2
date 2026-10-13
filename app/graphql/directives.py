from __future__ import annotations

from typing import Any

from ariadne import SchemaDirectiveVisitor
from graphql import default_field_resolver, GraphQLField, GraphQLObjectType, GraphQLInterfaceType


class _BaseAuthDirective(SchemaDirectiveVisitor):
    """Базовый класс: оборачивает резолвер проверкой, которую задаёт наследник."""

    def visit_field_definition(
        self,
        field: GraphQLField,
        object_type: GraphQLObjectType | GraphQLInterfaceType,
    ) -> GraphQLField:
        original_resolver = field.resolve or default_field_resolver

        def wrapped_resolver(obj: Any, info: Any, **kwargs: Any) -> Any:
            self.check_permission(info)
            return original_resolver(obj, info, **kwargs)

        field.resolve = wrapped_resolver
        return field

    def check_permission(self, info: Any) -> None:
        raise NotImplementedError


class IsAuthenticatedDirective(_BaseAuthDirective):
    def check_permission(self, info: Any) -> None:
        user = info.context.get("user") if info.context else None
        if user is None:
            raise Exception("Authentication required")


class IsAdminDirective(_BaseAuthDirective):
    def check_permission(self, info: Any) -> None:
        user = info.context.get("user") if info.context else None
        if user is None:
            raise Exception("Authentication required")
        if not user.is_admin:
            raise Exception("Admin only")