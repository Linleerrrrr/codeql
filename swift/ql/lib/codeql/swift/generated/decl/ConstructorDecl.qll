// generated by codegen/codegen.py
import codeql.swift.elements.decl.AbstractFunctionDecl

class ConstructorDeclBase extends @constructor_decl, AbstractFunctionDecl {
  override string getAPrimaryQlClass() { result = "ConstructorDecl" }
}