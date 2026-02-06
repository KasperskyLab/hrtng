#pragma once
bool unflattening(mbl_array_t *mba);
bool ufIsInWL(ea_t ea);
void ufAddWL(ea_t ea);
bool ufIsInGL(ea_t ea);
void ufAddGL(ea_t ea);
void ufDelGL(ea_t ea);
extern ea_t ufCurr;

bool SplitMblocksByJccEnding(mblock_t* pred1, mblock_t* pred2, mblock_t*& endsWithJcc, mblock_t*& nonJcc, int& jccDest, int& jccFallthrough);
