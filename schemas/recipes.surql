DEFINE TABLE OVERWRITE recipes SCHEMAFULL;

DEFINE FIELD OVERWRITE written_by ON recipes TYPE record<users>;
DEFINE FIELD OVERWRITE recipe_markdown ON recipes TYPE string;
DEFINE FIELD OVERWRITE title ON recipes TYPE string;
DEFINE FIELD OVERWRITE recipe_image ON recipes TYPE option<string> ASSERT $value.is_url();

DEFINE FIELD OVERWRITE recipe_embeddings ON recipes TYPE array<float>;
DEFINE INDEX OVERWRITE recipe_embeddings_index ON recipes FIELDS recipe_embeddings MTREE DIMENSION 1024 DIST COSINE;
# DEFINE FIELD OVERWRITE field ON recipes;