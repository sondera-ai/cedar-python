"""Define the Cedar Schema JSON Format in Pydantic"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator

from cedar import Schema, SchemaFragment


class SchemaType(BaseModel):
    """
    Represents a type definition in Cedar Schema.
    Used for attributes, shape, context, and commonTypes.
    """

    model_config = ConfigDict()

    # 'type' can be a primitive (String, Long, Boolean), a complex type (Record, Set),
    # a reference (Entity, Extension), or a custom common type name.
    type: str

    # 'required' is only valid within Record attributes in Cedar 3.0+
    # Defaults to true if not specified, only include if false
    required: bool | None = None

    # Specific fields based on the 'type'

    # For 'Record':
    attributes: dict[str, SchemaType] | None = None

    # For 'Set':
    element: SchemaType | None = None

    # For 'Entity', 'EntityOrCommon', 'Extension':
    name: str | None = None

    # Annotations can appear on type definitions (e.g. inside a Record attribute)
    annotations: dict[str, str] | None = None

    @model_validator(mode="after")
    def validate_type_structure(self) -> SchemaType:
        """
        Validates that the necessary fields are present for specific types.
        """
        t = self.type

        # 'Set' requires an 'element' definition
        if t == "Set" and self.element is None:
            raise ValueError(
                "Type 'Set' requires an 'element' field defining the set members."
            )

        # 'Entity', 'EntityOrCommon', and 'Extension' require a 'name'
        if t in ("Entity", "EntityOrCommon", "Extension") and not self.name:
            raise ValueError(f"Type '{t}' requires a 'name' field.")

        # 'Record' usually has 'attributes', but empty records (attributes=None or {}) are valid.

        return self


class EntityType(BaseModel):
    """
    Defines a principal or resource entity type.
    """

    memberOfTypes: list[str] | None = Field(
        default=None, description="List of parent entity types."
    )

    # 'shape' must be a Record type if present.
    # If omitted, it implies an empty record.
    shape: SchemaType | None = None

    # 'enum' is used for defining a fixed set of entity IDs (e.g. for groups/roles)
    enum: list[str] | None = None

    tags: SchemaType | None = Field(
        default=None, description="Type definition for tags (if allowed)."
    )

    annotations: dict[str, str] | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> EntityType:
        if self.shape and self.shape.type != "Record":
            # Note: Custom common types resolving to Record are allowed,
            # but strictly speaking the 'shape' literal usually defines a Record structure directly.
            # We warn or pass here. The schema doc says "shape element... must have type Record".
            pass
        return self


class ActionMember(BaseModel):
    """
    Represents membership in an Action Group.
    """

    id: str
    type: str | None = None  # Defaults to Action in current namespace if omitted


class AppliesTo(BaseModel):
    """
    Defines constraints on the action's usage (principal, resource, context).
    """

    principalTypes: list[str] | None = None
    resourceTypes: list[str] | None = None
    context: SchemaType | None = Field(
        default=None, description="Context must be a Record or Common Type."
    )


class Action(BaseModel):
    """
    Defines an Action entity.
    """

    memberOf: list[ActionMember] | None = None
    appliesTo: AppliesTo | None = None
    annotations: dict[str, str] | None = None


class NamespaceDefinition(BaseModel):
    """
    A collection of entity types, actions, and common types within a namespace.
    """

    entityTypes: dict[str, EntityType]
    actions: dict[str, Action]
    commonTypes: dict[str, SchemaType] | None = None
    annotations: dict[str, str] | None = None


class CedarSchema(RootModel):
    """
    The root Cedar Policy Schema object.
    Keys are Namespace strings (e.g., "PhotoFlash", "My::App").
    """

    root: dict[str, NamespaceDefinition]

    def __getitem__(self, item):
        return self.root[item]

    def into_schema(self) -> Schema:
        return Schema.from_json(self.model_dump_json(exclude_none=True))

    def into_schema_fragment(self) -> SchemaFragment:
        return SchemaFragment.from_json(self.model_dump_json(exclude_none=True))
