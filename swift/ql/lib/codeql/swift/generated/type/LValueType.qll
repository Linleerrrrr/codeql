// generated by codegen/codegen.py
import codeql.swift.elements.type.Type

class LValueTypeBase extends @l_value_type, Type {
  override string getAPrimaryQlClass() { result = "LValueType" }

  Type getObjectType() {
    exists(Type x |
      l_value_types(this, x) and
      result = x.resolve()
    )
  }
}