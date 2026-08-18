// Package auth provides user registration, authentication, and authorization.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/GagarinRu/gophkeeper/internal/storage"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const defaultTokenTTL = 24 * time.Hour

// contextKey is used for request context values.
type contextKey string

// UserIDKey is the context key for the authenticated user ID.
const UserIDKey contextKey = "userID"

// Service handles registration, login, and token validation.
type Service struct {
	store     storage.Storage
	jwtSecret []byte
	tokenTTL  time.Duration
}

// ServiceOption configures an auth service.
type ServiceOption func(*Service)

// WithTokenTTL sets the JWT lifetime.
func WithTokenTTL(ttl time.Duration) ServiceOption {
	return func(s *Service) {
		if ttl > 0 {
			s.tokenTTL = ttl
		}
	}
}

// NewService creates an auth service with the given JWT secret.
func NewService(store storage.Storage, jwtSecret string, opts ...ServiceOption) *Service {
	s := &Service{
		store:     store,
		jwtSecret: []byte(jwtSecret),
		tokenTTL:  defaultTokenTTL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// Register creates a user and returns an access token.
func (s *Service) Register(ctx context.Context, email, password string) (string, *models.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, fmt.Errorf("hash password: %w", err)
	}
	existing, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		return "", nil, err
	}
	if existing != nil {
		return "", nil, errors.New("user already exists")
	}
	user, err := s.store.CreateUser(ctx, email, string(hash))
	if err != nil {
		return "", nil, err
	}
	token, err := s.issueToken(user)
	if err != nil {
		return "", nil, err
	}
	return token, user, nil
}

// Login authenticates a user and returns an access token.
func (s *Service) Login(ctx context.Context, email, password string) (string, *models.User, error) {
	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		return "", nil, err
	}
	if user == nil {
		return "", nil, errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", nil, errors.New("invalid credentials")
	}
	token, err := s.issueToken(user)
	if err != nil {
		return "", nil, err
	}
	return token, user, nil
}

// Logout revokes the given access token.
func (s *Service) Logout(ctx context.Context, tokenStr string) error {
	claims, err := s.parseClaims(tokenStr)
	if err != nil {
		return err
	}
	if claims.ID == "" || claims.ExpiresAt == nil {
		return errors.New("invalid token")
	}
	return s.store.RevokeToken(ctx, claims.ID, claims.ExpiresAt.Time)
}

// ValidateToken parses a JWT and returns the user ID.
func (s *Service) ValidateToken(ctx context.Context, tokenStr string) (string, error) {
	claims, err := s.parseClaims(tokenStr)
	if err != nil {
		return "", err
	}
	if claims.UserID == "" {
		return "", errors.New("invalid token")
	}
	revoked, err := s.store.IsTokenRevoked(ctx, claims.ID)
	if err != nil {
		return "", err
	}
	if revoked {
		return "", errors.New("invalid token")
	}
	return claims.UserID, nil
}

func (s *Service) parseClaims(tokenStr string) (*claims, error) {
	claims := &claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

func (s *Service) issueToken(user *models.User) (string, error) {
	now := time.Now()
	claims := claims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// BearerToken extracts the token from an Authorization header.
func BearerToken(header string) (string, bool) {
	if header == "" {
		return "", false
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	return token, token != ""
}

// UserIDFromContext returns the authenticated user ID from context.
func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(UserIDKey).(string)
	return id, ok && id != ""
}
