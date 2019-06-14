package web

type AuthenticationType string

const (
	Basic  AuthenticationType = "Basic"
	Bearer AuthenticationType = "Bearer"
)

// UserContext holds the information for the current user
type UserContext struct {
	DataFunc           func(data interface{}) error
	AuthenticationType AuthenticationType
	Name               string
}
