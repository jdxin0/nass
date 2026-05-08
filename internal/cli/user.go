package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/jdxin0/nass/internal/auth"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func userCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage users",
	}
	cmd.AddCommand(userAddCmd(), userListCmd(), userRmCmd(), userPasswdCmd())
	return cmd
}

func userAddCmd() *cobra.Command {
	var (
		email    string
		isAdmin  bool
		password string
	)
	cmd := &cobra.Command{
		Use:   "add <username>",
		Short: "Create a user (admin-only operation; no public sign-up)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(func(c context.Context, s *auth.Store) error {
				pw, err := resolvePassword(password, "Password: ")
				if err != nil {
					return err
				}
				u, err := s.Create(c, args[0], email, pw, isAdmin)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "created user %q (id=%d, admin=%t)\n", u.Username, u.ID, u.IsAdmin)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "email address")
	cmd.Flags().BoolVar(&isAdmin, "admin", false, "grant admin privileges")
	cmd.Flags().StringVar(&password, "password", "", "password (omit to read from stdin)")
	return cmd
}

func userListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List users",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(func(c context.Context, s *auth.Store) error {
				users, err := s.List(c)
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "ID\tUSERNAME\tEMAIL\tADMIN\tCREATED")
				for _, u := range users {
					fmt.Fprintf(w, "%d\t%s\t%s\t%t\t%s\n", u.ID, u.Username, u.Email, u.IsAdmin, u.CreatedAt.Format("2006-01-02"))
				}
				return w.Flush()
			})
		},
	}
}

func userRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <username>",
		Short: "Delete a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(func(c context.Context, s *auth.Store) error {
				u, err := s.GetByUsername(c, args[0])
				if err != nil {
					return err
				}
				if err := s.Delete(c, u.ID); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "deleted user %q\n", u.Username)
				return nil
			})
		},
	}
}

func userPasswdCmd() *cobra.Command {
	var password string
	cmd := &cobra.Command{
		Use:   "passwd <username>",
		Short: "Change a user's password",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(func(c context.Context, s *auth.Store) error {
				u, err := s.GetByUsername(c, args[0])
				if err != nil {
					return err
				}
				pw, err := resolvePassword(password, "New password: ")
				if err != nil {
					return err
				}
				if err := s.SetPassword(c, u.ID, pw); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "updated password for %q\n", u.Username)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&password, "password", "", "new password (omit to read from stdin)")
	return cmd
}

func resolvePassword(flag, prompt string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if env := os.Getenv("NASS_PASSWORD"); env != "" {
		return env, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("password not provided and stdin is not a terminal; pass --password or set NASS_PASSWORD")
	}
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

// parseID is a helper for future commands taking a numeric user id.
func parseID(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

var _ = parseID
