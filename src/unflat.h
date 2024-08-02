#pragma once
bool unflattening(mbl_array_t *mba);
bool ufIsInWL(ea_t ea);
void ufAddWL(ea_t ea);
bool ufIsInGL(ea_t ea);
void ufAddGL(ea_t ea);
void ufDelGL(ea_t ea);
extern ea_t ufCurr;
