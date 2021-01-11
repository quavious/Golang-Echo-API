package model

// Post contains title, content of one post.
type Post struct {
	Title   string `json:"title"`
	Content string `json:"content"`
	AdLink  string `json:"adLink"`
}
