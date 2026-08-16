package storage

import (
	"errors"
	"testing"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestIsRetriableDBError(t *testing.T) {
	require.False(t, isRetriableDBError(nil))
	require.False(t, isRetriableDBError(errors.New("generic")))

	pgErr := &pgconn.PgError{Code: pgerrcode.DeadlockDetected}
	require.True(t, isRetriableDBError(pgErr))

	connErr := &pgconn.PgError{Code: pgerrcode.ConnectionFailure}
	require.True(t, isRetriableDBError(connErr))

	other := &pgconn.PgError{Code: "23505"}
	require.False(t, isRetriableDBError(other))
}
