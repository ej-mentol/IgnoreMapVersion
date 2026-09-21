#pragma once

#include <stdint.h>

#define BSPVERSION 30
#define HEADER_LUMPS 15

#define LUMP_ENTITIES     0
#define LUMP_PLANES       1
#define LUMP_TEXTURES     2
#define LUMP_VERTICES     3
#define LUMP_VISIBILITY   4
#define LUMP_NODES        5
#define LUMP_TEXINFO      6
#define LUMP_FACES        7
#define LUMP_LIGHTING     8
#define LUMP_CLIPNODES    9
#define LUMP_LEAVES       10
#define LUMP_MARKSURFACES 11
#define LUMP_EDGES        12
#define LUMP_SURFEDGES    13
#define LUMP_MODELS       14

struct bsp_lump_t
{
	int32_t fileofs;
	int32_t filelen;
};

struct bsp_header_t
{
	int32_t version;
	bsp_lump_t lumps[HEADER_LUMPS];
};

enum class BSPSafetyVerdict
{
	Valid,
	FileNotFound,
	InvalidVersion,
	TruncatedFile,
	CorruptGeometry
};

struct BSPValidationResult
{
	BSPSafetyVerdict verdict;
	int32_t version;
	int64_t fileSize;
	int32_t clipnodesBytes;
	int32_t planesBytes;
	int32_t modelsBytes;
	int32_t entitiesBytes;
};

BSPValidationResult ValidateBSPFile(const char* pszMapPath);
const char* GetBSPSafetyVerdictString(BSPSafetyVerdict verdict);
