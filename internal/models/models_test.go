package models_test

import (
	"testing"

	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/stretchr/testify/require"
)

func TestValidSecretType(t *testing.T) {
	require.True(t, models.ValidSecretType(models.SecretTypeLoginPassword))
	require.True(t, models.ValidSecretType(models.SecretTypeText))
	require.True(t, models.ValidSecretType(models.SecretTypeBinary))
	require.True(t, models.ValidSecretType(models.SecretTypeCard))
	require.False(t, models.ValidSecretType("unknown"))
}
