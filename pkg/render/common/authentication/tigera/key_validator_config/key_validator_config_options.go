package keyvalidatorconfig

type Option func(*KeyValidatorConfig)

func WithUsernameClaim(usernameClaim string) Option {
	return func(config *KeyValidatorConfig) {
		config.usernameClaim = usernameClaim
	}
}

func WithGroupsClaim(groupClaim string) Option {
	return func(config *KeyValidatorConfig) {
		config.groupsClaim = groupClaim
	}
}

func WithUsernamePrefix(usernamePrefix string) Option {
	return func(config *KeyValidatorConfig) {
		config.usernamePrefix = usernamePrefix
	}
}

func WithGroupsPrefix(groupsPrefix string) Option {
	return func(config *KeyValidatorConfig) {
		config.groupsClaim = groupsPrefix
	}
}
