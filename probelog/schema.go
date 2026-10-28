package probelog

import _ "embed"

// schemaSQL 是新安装的建表语句，测试用它核对事件模型的列都在表里
//
//go:embed schema.sql
var schemaSQL string
