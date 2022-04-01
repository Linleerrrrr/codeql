// generated by codegen/codegen.py
import codeql.swift.elements.decl.Decl
import codeql.swift.elements.decl.GenericContext
import codeql.swift.elements.decl.IterableDeclContext
import codeql.swift.elements.decl.NominalTypeDecl

class ExtensionDeclBase extends @extension_decl, Decl, GenericContext, IterableDeclContext {
  override string getAPrimaryQlClass() { result = "ExtensionDecl" }

  NominalTypeDecl getExtendedTypeDecl() {
    exists(NominalTypeDecl x |
      extension_decls(this, x) and
      result = x.resolve()
    )
  }
}