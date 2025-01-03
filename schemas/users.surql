DEFINE TABLE OVERWRITE users SCHEMAFULL;

DEFINE FIELD OVERWRITE username ON users TYPE string;
DEFINE INDEX OVERWRITE unique_username ON users FIELDS username UNIQUE;
DEFINE FIELD OVERWRITE hash ON users TYPE string;
DEFINE FIELD OVERWRITE bio ON users TYPE option<string>;
DEFINE FIELD OVERWRITE avatar_url ON users TYPE option<string> ASSERT $value.is_url();