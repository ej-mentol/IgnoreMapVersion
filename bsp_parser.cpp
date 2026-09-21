#include "bsp_parser.h"
#include "plugins.h"
#include <stdio.h>
#include <string.h>

static bool ValidateParsedHeader(const bsp_header_t& header, int64_t fileSize, BSPValidationResult& res)
{
	res.version = header.version;
	if (header.version != BSPVERSION)
	{
		res.verdict = BSPSafetyVerdict::InvalidVersion;
		return false;
	}

	res.clipnodesBytes = header.lumps[LUMP_CLIPNODES].filelen;
	res.planesBytes = header.lumps[LUMP_PLANES].filelen;
	res.modelsBytes = header.lumps[LUMP_MODELS].filelen;
	res.entitiesBytes = header.lumps[LUMP_ENTITIES].filelen;

	// Verify lump offsets do not exceed file size
	for (int i = 0; i < HEADER_LUMPS; ++i)
	{
		int64_t lumpEnd = (int64_t)header.lumps[i].fileofs + header.lumps[i].filelen;
		if (lumpEnd > fileSize || header.lumps[i].fileofs < 0 || header.lumps[i].filelen < 0)
		{
			res.verdict = BSPSafetyVerdict::TruncatedFile;
			return false;
		}
	}

	// Verify critical geometry lumps exist: clipnodes (collisions), planes (geometry), entities (worldspawn)
	if (res.clipnodesBytes <= 0 || res.planesBytes <= 0 || res.entitiesBytes <= 0)
	{
		res.verdict = BSPSafetyVerdict::CorruptGeometry;
		return false;
	}

	res.verdict = BSPSafetyVerdict::Valid;
	return true;
}

BSPValidationResult ValidateBSPFile(const char* pszMapPath)
{
	BSPValidationResult res = {};
	res.verdict = BSPSafetyVerdict::FileNotFound;

	if (!pszMapPath || !pszMapPath[0])
		return res;

	char szCleanPath[MAX_PATH];
	strncpy(szCleanPath, pszMapPath, sizeof(szCleanPath) - 1);
	szCleanPath[sizeof(szCleanPath) - 1] = 0;

	// Normalize slashes
	for (char* p = szCleanPath; *p; ++p)
	{
		if (*p == '\\')
			*p = '/';
	}

	// 1. Try reading via engine FileSystem (IFileSystem / IFileSystem_HL25)
	{
		__try
		{
			FileHandle_t hFile = nullptr;

			if (g_pFileSystem_HL25)
				hFile = g_pFileSystem_HL25->Open(szCleanPath, "rb");
			else if (g_pFileSystem)
				hFile = g_pFileSystem->Open(szCleanPath, "rb");
			if (hFile)
			{
				res.fileSize = FILESYSTEM_ANY_SIZE(hFile);
				if (res.fileSize >= (int64_t)sizeof(bsp_header_t))
				{
					bsp_header_t header = {};
					int bytesRead = FILESYSTEM_ANY_READ(&header, sizeof(header), hFile);
					FILESYSTEM_ANY_CLOSE(hFile);

					if (bytesRead == (int)sizeof(header))
					{
						ValidateParsedHeader(header, res.fileSize, res);
						return res;
					}
					else
					{
						res.verdict = BSPSafetyVerdict::TruncatedFile;
						return res;
					}
				}
				else
				{
					FILESYSTEM_ANY_CLOSE(hFile);
					res.verdict = BSPSafetyVerdict::TruncatedFile;
					return res;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			// Safe fallback to CRT fopen below
		}
	}

	// 2. Fallback to standard CRT fopen (used if called before filesystem mount or for direct disk files)
	FILE* fp = fopen(szCleanPath, "rb");
	if (!fp)
		return res;

	fseek(fp, 0, SEEK_END);
	res.fileSize = _ftelli64(fp);
	fseek(fp, 0, SEEK_SET);

	if (res.fileSize < (int64_t)sizeof(bsp_header_t))
	{
		fclose(fp);
		res.verdict = BSPSafetyVerdict::TruncatedFile;
		return res;
	}

	bsp_header_t header = {};
	size_t readCount = fread(&header, 1, sizeof(header), fp);
	fclose(fp);

	if (readCount != sizeof(header))
	{
		res.verdict = BSPSafetyVerdict::TruncatedFile;
		return res;
	}

	ValidateParsedHeader(header, res.fileSize, res);
	return res;
}

const char* GetBSPSafetyVerdictString(BSPSafetyVerdict verdict)
{
	switch (verdict)
	{
	case BSPSafetyVerdict::Valid:
		return "Valid";
	case BSPSafetyVerdict::FileNotFound:
		return "File Not Found";
	case BSPSafetyVerdict::InvalidVersion:
		return "Invalid BSP Version";
	case BSPSafetyVerdict::TruncatedFile:
		return "Truncated File";
	case BSPSafetyVerdict::CorruptGeometry:
		return "Corrupt Geometry Lumps";
	default:
		return "Unknown";
	}
}
