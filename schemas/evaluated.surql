DEFINE TABLE OVERWRITE evaluated SCHEMAFULL TYPE RELATION IN users OUT recipes;

DEFINE FIELD OVERWRITE stars ON evaluated TYPE number ASSERT ($value >= 0 AND $value <= 5);

# DEFINE FIELD OVERWRITE field ON read_recipe;