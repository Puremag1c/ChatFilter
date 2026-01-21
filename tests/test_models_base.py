"""Comprehensive tests for src/chatfilter/models/base.py.

Tests the StrictModelConfig base class configuration and its behavior
when inherited by Pydantic models.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from chatfilter.models.base import StrictModelConfig


class TestStrictModelConfig:
    """Test StrictModelConfig base class configuration."""

    def test_config_has_strict_mode(self):
        """Test that StrictModelConfig has strict=True in model_config."""
        assert StrictModelConfig.model_config["strict"] is True

    def test_config_has_frozen(self):
        """Test that StrictModelConfig has frozen=True in model_config."""
        assert StrictModelConfig.model_config["frozen"] is True

    def test_config_has_extra_forbid(self):
        """Test that StrictModelConfig has extra='forbid' in model_config."""
        assert StrictModelConfig.model_config["extra"] == "forbid"

    def test_config_dict_keys(self):
        """Test that model_config has exactly the expected keys."""
        expected_keys = {"strict", "frozen", "extra"}
        actual_keys = set(StrictModelConfig.model_config.keys())
        assert actual_keys == expected_keys


class TestStrictValidation:
    """Test strict validation behavior when using StrictModelConfig."""

    def test_strict_validation_rejects_wrong_type(self):
        """Test that strict validation rejects wrong types (e.g., string for int)."""

        class StrictModel(BaseModel, StrictModelConfig):
            value: int

        # Should reject string when expecting int in strict mode
        with pytest.raises(ValidationError) as exc_info:
            StrictModel(value="123")

        assert "int_type" in str(exc_info.value)

    def test_strict_validation_accepts_correct_type(self):
        """Test that strict validation accepts correct types."""

        class StrictModel(BaseModel, StrictModelConfig):
            value: int

        model = StrictModel(value=123)
        assert model.value == 123

    def test_strict_validation_rejects_float_for_int(self):
        """Test that strict validation rejects float when int is expected."""

        class StrictModel(BaseModel, StrictModelConfig):
            value: int

        with pytest.raises(ValidationError) as exc_info:
            StrictModel(value=123.45)

        assert "int_type" in str(exc_info.value)

    def test_strict_validation_rejects_bool_for_int(self):
        """Test that strict validation rejects bool when int is expected."""

        class StrictModel(BaseModel, StrictModelConfig):
            value: int

        # In strict mode, bool should not be coerced to int
        with pytest.raises(ValidationError):
            StrictModel(value=True)

    def test_strict_validation_multiple_fields(self):
        """Test that strict validation works with multiple fields."""

        class StrictModel(BaseModel, StrictModelConfig):
            number: int
            text: str
            flag: bool

        # Valid data
        model = StrictModel(number=42, text="hello", flag=True)
        assert model.number == 42
        assert model.text == "hello"
        assert model.flag is True

        # Invalid data (wrong type for number)
        with pytest.raises(ValidationError):
            StrictModel(number="42", text="hello", flag=True)


class TestFrozenBehavior:
    """Test frozen (immutable) behavior when using StrictModelConfig."""

    def test_frozen_prevents_attribute_modification(self):
        """Test that frozen=True prevents modifying attributes after creation."""

        class FrozenModel(BaseModel, StrictModelConfig):
            value: int

        model = FrozenModel(value=42)

        with pytest.raises(ValidationError, match="frozen"):
            model.value = 100

    def test_frozen_prevents_attribute_deletion(self):
        """Test that frozen=True prevents deleting attributes."""

        class FrozenModel(BaseModel, StrictModelConfig):
            value: int

        model = FrozenModel(value=42)

        with pytest.raises(ValidationError, match="frozen"):
            del model.value

    def test_frozen_allows_multiple_reads(self):
        """Test that frozen models allow reading attributes multiple times."""

        class FrozenModel(BaseModel, StrictModelConfig):
            value: int

        model = FrozenModel(value=42)

        # Should be able to read multiple times
        assert model.value == 42
        assert model.value == 42
        assert model.value == 42

    def test_frozen_with_optional_fields(self):
        """Test that frozen works correctly with optional fields."""

        class FrozenModel(BaseModel, StrictModelConfig):
            required: int
            optional: str | None = None

        model = FrozenModel(required=42)

        with pytest.raises(ValidationError, match="frozen"):
            model.optional = "new value"


class TestExtraForbid:
    """Test extra='forbid' behavior when using StrictModelConfig."""

    def test_extra_forbid_rejects_unknown_fields(self):
        """Test that extra='forbid' rejects unknown fields during construction."""

        class StrictModel(BaseModel, StrictModelConfig):
            value: int

        with pytest.raises(ValidationError, match="extra"):
            StrictModel(value=42, unknown_field="should fail")

    def test_extra_forbid_accepts_defined_fields(self):
        """Test that extra='forbid' accepts all defined fields."""

        class StrictModel(BaseModel, StrictModelConfig):
            field1: int
            field2: str
            field3: bool

        model = StrictModel(field1=42, field2="hello", field3=True)
        assert model.field1 == 42
        assert model.field2 == "hello"
        assert model.field3 is True

    def test_extra_forbid_with_optional_fields(self):
        """Test that extra='forbid' works with optional fields."""

        class StrictModel(BaseModel, StrictModelConfig):
            required: int
            optional: str | None = None

        # Valid: providing optional field
        model1 = StrictModel(required=42, optional="value")
        assert model1.optional == "value"

        # Valid: omitting optional field
        model2 = StrictModel(required=42)
        assert model2.optional is None

        # Invalid: providing unknown field
        with pytest.raises(ValidationError, match="extra"):
            StrictModel(required=42, unknown="should fail")

    def test_extra_forbid_prevents_dynamic_attributes(self):
        """Test that extra='forbid' prevents adding attributes after creation."""

        class StrictModel(BaseModel, StrictModelConfig):
            value: int

        model = StrictModel(value=42)

        # Should not be able to add new attributes (also prevented by frozen)
        with pytest.raises((ValidationError, AttributeError)):
            model.new_field = "should fail"


class TestInheritanceBehavior:
    """Test that StrictModelConfig works correctly with inheritance."""

    def test_inheritance_preserves_strict_validation(self):
        """Test that inheriting from StrictModelConfig preserves strict validation."""

        class BaseStrictModel(BaseModel, StrictModelConfig):
            base_field: int

        class DerivedModel(BaseStrictModel):
            derived_field: str

        # Should inherit strict validation
        with pytest.raises(ValidationError):
            DerivedModel(base_field="not an int", derived_field="text")

    def test_inheritance_preserves_frozen(self):
        """Test that inheriting from StrictModelConfig preserves frozen behavior."""

        class BaseStrictModel(BaseModel, StrictModelConfig):
            base_field: int

        class DerivedModel(BaseStrictModel):
            derived_field: str

        model = DerivedModel(base_field=42, derived_field="hello")

        # Should inherit frozen behavior
        with pytest.raises(ValidationError, match="frozen"):
            model.base_field = 100

    def test_inheritance_preserves_extra_forbid(self):
        """Test that inheriting from StrictModelConfig preserves extra='forbid'."""

        class BaseStrictModel(BaseModel, StrictModelConfig):
            base_field: int

        class DerivedModel(BaseStrictModel):
            derived_field: str

        # Should inherit extra='forbid'
        with pytest.raises(ValidationError, match="extra"):
            DerivedModel(base_field=42, derived_field="hello", extra="not allowed")

    def test_multiple_inheritance_levels(self):
        """Test that StrictModelConfig works with multiple inheritance levels."""

        class Level1(BaseModel, StrictModelConfig):
            field1: int

        class Level2(Level1):
            field2: str

        class Level3(Level2):
            field3: bool

        model = Level3(field1=42, field2="hello", field3=True)
        assert model.field1 == 42
        assert model.field2 == "hello"
        assert model.field3 is True

        # Should still enforce all config rules at deepest level
        with pytest.raises(ValidationError, match="frozen"):
            model.field1 = 100


class TestEdgeCases:
    """Test edge cases and boundary conditions for StrictModelConfig."""

    def test_empty_model_with_config(self):
        """Test that StrictModelConfig works with a model that has no fields."""

        class EmptyModel(BaseModel, StrictModelConfig):
            pass

        model = EmptyModel()
        assert model is not None

        # Should still forbid extra fields
        with pytest.raises(ValidationError, match="extra"):
            EmptyModel(unexpected="field")

    def test_model_with_complex_types(self):
        """Test that StrictModelConfig works with complex field types."""
        from datetime import datetime

        class ComplexModel(BaseModel, StrictModelConfig):
            timestamp: datetime
            items: list[int]
            mapping: dict[str, int]

        from datetime import UTC

        now = datetime.now(UTC)
        model = ComplexModel(timestamp=now, items=[1, 2, 3], mapping={"a": 1, "b": 2})

        assert model.timestamp == now
        assert model.items == [1, 2, 3]
        assert model.mapping == {"a": 1, "b": 2}

        # Should still be frozen
        with pytest.raises(ValidationError, match="frozen"):
            model.items = [4, 5, 6]

    def test_model_with_nested_models(self):
        """Test that StrictModelConfig works with nested models."""

        class InnerModel(BaseModel, StrictModelConfig):
            value: int

        class OuterModel(BaseModel, StrictModelConfig):
            inner: InnerModel
            name: str

        inner = InnerModel(value=42)
        outer = OuterModel(inner=inner, name="test")

        assert outer.inner.value == 42
        assert outer.name == "test"

        # Both should be frozen
        with pytest.raises(ValidationError, match="frozen"):
            outer.name = "new name"

        with pytest.raises(ValidationError, match="frozen"):
            inner.value = 100

    def test_model_with_defaults(self):
        """Test that StrictModelConfig works with default values."""

        class ModelWithDefaults(BaseModel, StrictModelConfig):
            required: int
            optional: str = "default"
            nullable: int | None = None

        # All defaults
        model1 = ModelWithDefaults(required=42)
        assert model1.required == 42
        assert model1.optional == "default"
        assert model1.nullable is None

        # Override defaults
        model2 = ModelWithDefaults(required=42, optional="custom", nullable=100)
        assert model2.optional == "custom"
        assert model2.nullable == 100

        # Should still be frozen
        with pytest.raises(ValidationError, match="frozen"):
            model1.optional = "new value"

    def test_model_equality_with_frozen(self):
        """Test that frozen models can be compared for equality."""

        class FrozenModel(BaseModel, StrictModelConfig):
            value: int
            text: str

        model1 = FrozenModel(value=42, text="hello")
        model2 = FrozenModel(value=42, text="hello")
        model3 = FrozenModel(value=100, text="world")

        # Same values should be equal
        assert model1 == model2

        # Different values should not be equal
        assert model1 != model3

    def test_model_hashing_with_frozen(self):
        """Test that frozen models are hashable and can be used in sets."""

        class FrozenModel(BaseModel, StrictModelConfig):
            value: int

        model1 = FrozenModel(value=42)
        model2 = FrozenModel(value=42)
        model3 = FrozenModel(value=100)

        # Should be hashable
        model_set = {model1, model2, model3}

        # model1 and model2 have same values, so set should have 2 elements
        assert len(model_set) == 2

    def test_model_json_serialization(self):
        """Test that models with StrictModelConfig can be serialized to JSON."""

        class SerializableModel(BaseModel, StrictModelConfig):
            number: int
            text: str
            flag: bool

        model = SerializableModel(number=42, text="hello", flag=True)

        # Should be serializable to JSON
        json_str = model.model_dump_json()
        assert "42" in json_str
        assert "hello" in json_str
        assert "true" in json_str

    def test_model_dict_conversion(self):
        """Test that models with StrictModelConfig can be converted to dict."""

        class DictModel(BaseModel, StrictModelConfig):
            number: int
            text: str

        model = DictModel(number=42, text="hello")
        model_dict = model.model_dump()

        assert model_dict == {"number": 42, "text": "hello"}

    def test_model_with_validators(self):
        """Test that StrictModelConfig works with custom validators."""
        from pydantic import field_validator

        class ValidatedModel(BaseModel, StrictModelConfig):
            value: int

            @field_validator("value")
            @classmethod
            def value_must_be_positive(cls, v: int) -> int:
                if v <= 0:
                    raise ValueError("value must be positive")
                return v

        # Valid value
        model = ValidatedModel(value=42)
        assert model.value == 42

        # Invalid value (custom validator)
        with pytest.raises(ValidationError, match="value must be positive"):
            ValidatedModel(value=-1)

        # Invalid type (strict validation)
        with pytest.raises(ValidationError):
            ValidatedModel(value="42")
