(function_declaration
  "fn" @context
  name: (identifier) @name) @item

(type_declaration
  "type" @context
  name: (type_identifier) @name) @item

(constructor
  name: (type_identifier) @name) @item

(const_declaration
  "const" @context
  name: (_) @name) @item
