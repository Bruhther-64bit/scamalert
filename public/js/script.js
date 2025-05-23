document.addEventListener("DOMContentLoaded", function () {
  // DOM elements
  const postBtn = document.getElementById("postBtn");
  const postModal = new bootstrap.Modal(document.getElementById("postModal"));
  const postForm = document.getElementById("postForm");
  const postsContainer = document.getElementById("postsContainer");

  // Load posts
  loadPosts();

  // Event listeners
  if (postBtn) {
    postBtn.addEventListener("click", () => {
      postModal.show();
    });
  }

  if (postForm) {
    postForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const content = document.getElementById("postContent").value;

      try {
        const response = await fetch("/posts", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: `content=${encodeURIComponent(content)}`,
        });

        if (response.ok) {
          postModal.hide();
          postForm.reset();
          loadPosts();
        }
      } catch (error) {
        console.error("Error posting:", error);
      }
    });
  }

  // Function to load posts
  async function loadPosts() {
    if (!postsContainer) return;

    try {
      const response = await fetch("/posts");
      const posts = await response.json();

      postsContainer.innerHTML = "";

      if (posts.length === 0) {
        postsContainer.innerHTML = "<p>No posts yet. Be the first to post!</p>";
        return;
      }

      posts.forEach((post) => {
        const postElement = document.createElement("div");
        postElement.className = "col-md-6 mb-3";
        postElement.innerHTML = `
                    <div class="card">
                        <div class="card-body">
                            <p class="card-text">${post.content}</p>
                            <small class="text-muted">${new Date(
                              post.timestamp
                            ).toLocaleString()}</small>
                        </div>
                    </div>
                `;
        postsContainer.appendChild(postElement);
      });
    } catch (error) {
      console.error("Error loading posts:", error);
    }
  }
});
