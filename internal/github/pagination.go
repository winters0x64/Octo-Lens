package github

import (
	"context"
	"time"

	"github.com/google/go-github/v68/github"
)

// Paginate fetches all pages from a paginated GitHub API endpoint.
// It respects rate limits by sleeping when remaining requests are low.
func Paginate[T any](ctx context.Context, fetch func(opts github.ListOptions) ([]T, *github.Response, error)) ([]T, error) {
	var all []T
	opts := github.ListOptions{PerPage: 100}

	for {
		items, resp, err := fetch(opts)
		if err != nil {
			return all, err
		}

		all = append(all, items...)

		if resp.NextPage == 0 {
			break
		}

		// Rate limit awareness: sleep if running low
		if resp.Rate.Remaining < 100 {
			sleepUntil := time.Until(resp.Rate.Reset.Time)
			if sleepUntil > 0 {
				select {
				case <-ctx.Done():
					return all, ctx.Err()
				case <-time.After(sleepUntil):
				}
			}
		}

		opts.Page = resp.NextPage
	}

	return all, nil
}
