package auth_test

import (
	"context"
	"testing"

	"github.com/GagarinRu/gophkeeper/internal/auth"
	"github.com/GagarinRu/gophkeeper/internal/storage"
	"github.com/stretchr/testify/require"
)

func TestServiceRegisterLoginValidate(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemStorage()
	svc := auth.NewService(store, "test-secret")

	token, user, err := svc.Register(ctx, "user@example.com", "password123")
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, user.ID)

	userID, err := svc.ValidateToken(ctx, token)
	require.NoError(t, err)
	require.Equal(t, user.ID, userID)

	loginToken, loginUser, err := svc.Login(ctx, "user@example.com", "password123")
	require.NoError(t, err)
	require.Equal(t, user.ID, loginUser.ID)
	require.NotEmpty(t, loginToken)

	_, _, err = svc.Login(ctx, "user@example.com", "wrong")
	require.Error(t, err)

	require.NoError(t, svc.Logout(ctx, token))
	_, err = svc.ValidateToken(ctx, token)
	require.Error(t, err)
}
