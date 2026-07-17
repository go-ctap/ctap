package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var origDataForCompress = []byte("hello world! hello world! hello world!")

func TestCompressDecompress(t *testing.T) {
	compressed, err := compress(origDataForCompress)
	require.NoError(t, err)

	decompressed, err := decompress(compressed)
	require.NoError(t, err)

	assert.Equal(t, origDataForCompress, decompressed)
}

func TestCompressDecompressLargeBlobData(t *testing.T) {
	compressed, err := CompressLargeBlobData(origDataForCompress)
	require.NoError(t, err)

	decompressed, err := DecompressLargeBlobData(compressed, uint(len(origDataForCompress)))
	require.NoError(t, err)
	assert.Equal(t, origDataForCompress, decompressed)

	_, err = DecompressLargeBlobData(compressed, uint(len(origDataForCompress)-1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "orig size mismatch")
}

func TestLargeBlobDataSizeLimit(t *testing.T) {
	_, err := CompressLargeBlobData(make([]byte, MaxLargeBlobDataSize+1))
	require.Error(t, err)

	_, err = DecompressLargeBlobData(nil, MaxLargeBlobDataSize+1)
	require.Error(t, err)
}
