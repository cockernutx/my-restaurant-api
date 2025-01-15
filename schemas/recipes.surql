DEFINE TABLE OVERWRITE recipes SCHEMAFULL;

DEFINE FIELD OVERWRITE written_by ON recipes TYPE record<users>;
DEFINE FIELD OVERWRITE recipe_markdown ON recipes TYPE string;
DEFINE FIELD OVERWRITE title ON recipes TYPE string;
DEFINE FIELD OVERWRITE recipe_image ON recipes TYPE option<string> ASSERT $value.is_url();
DEFINE FIELD OVERWRITE embeddings ON recipes TYPE array<record<recipe_embeddings>>;

DEFINE TABLE OVERWRITE recipe_embeddings SCHEMAFULL;

DEFINE FIELD OVERWRITE refers_to ON recipe_embeddings TYPE record<recipes>;
DEFINE FIELD OVERWRITE embeddings ON recipe_embeddings TYPE array<float>;
DEFINE INDEX OVERWRITE embeddings_index ON recipe_embeddings FIELDS embeddings MTREE DIMENSION 1024 DIST COSINE;
# DEFINE FIELD OVERWRITE field ON recipes;