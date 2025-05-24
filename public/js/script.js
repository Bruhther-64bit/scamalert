document.addEventListener("DOMContentLoaded", function () {
  // DOM elements
  const postBtn = document.getElementById("postBtn");
  const postInput = document.getElementById("postInput");
  const postModal = new bootstrap.Modal(document.getElementById("postModal"));
  const postForm = document.getElementById("postForm");
  const postsContainer = document.getElementById("postsContainer");
  const editPostModal = new bootstrap.Modal(document.getElementById("editPostModal"));
  const editPostForm = document.getElementById("editPostForm");

  // Event listeners
  if (postBtn) {
    postBtn.addEventListener("click", () => {
      postModal.show();
    });
  }

  if (postInput) {
    postInput.addEventListener("click", () => {
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
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            content,
            userId: typeof currentUserId !== 'undefined' ? currentUserId : null
          }),
        });

        if (response.ok) {
          const data = await response.json();
          addNewPostToDOM(data.post);
          postModal.hide();
          postForm.reset();
        }
      } catch (error) {
        console.error("Error posting:", error);
      }
    });
  }

  // Edit Post
  document.addEventListener('click', async function(e) {
    if (e.target.classList.contains('edit-post') || e.target.closest('.edit-post')) {
      const postElement = e.target.closest('.post');
      const postId = postElement.dataset.postId;
      const postContent = postElement.querySelector('.card-text').textContent;
      
      document.getElementById('editPostId').value = postId;
      document.getElementById('editPostContent').value = postContent;
    }

    // Delete Post
    if (e.target.classList.contains('delete-post') || e.target.closest('.delete-post')) {
      if (!confirm('Are you sure you want to delete this post?')) return;
      
      const postElement = e.target.closest('.post');
      const postId = postElement.dataset.postId;
      
      try {
        const response = await fetch(`/posts/${postId}`, {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ userId: typeof currentUserId !== 'undefined' ? currentUserId : null })
        });

        if (response.ok) {
          postElement.remove();
        }
      } catch (error) {
        console.error('Error deleting post:', error);
      }
    }
  });

  // Update Post
  if (editPostForm) {
    editPostForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const postId = document.getElementById('editPostId').value;
      const content = document.getElementById('editPostContent').value;
      
      try {
        const response = await fetch(`/posts/${postId}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ content })
        });

        if (response.ok) {
          const data = await response.json();
          const postElement = document.querySelector(`.post[data-post-id="${postId}"]`);
          if (postElement) {
            postElement.querySelector('.card-text').textContent = data.post.content;
          }
          editPostModal.hide();
        }
      } catch (error) {
        console.error('Error updating post:', error);
      }
    });
  }

  // Function to add new post to DOM
  function addNewPostToDOM(post) {
    if (!postsContainer) return;

    const postElement = document.createElement('div');
    postElement.className = 'post card mb-3';
    postElement.dataset.postId = post._id;
    postElement.innerHTML = `
      <div class="card-body">
        <div class="post-actions float-end">
          <button class="btn btn-sm btn-outline-secondary edit-post" data-bs-toggle="modal" data-bs-target="#editPostModal">
            <i class="fas fa-edit"></i>
          </button>
          <button class="btn btn-sm btn-outline-danger delete-post">
            <i class="fas fa-trash"></i>
          </button>
        </div>
        <p class="card-text">${post.content}</p>
        <small class="text-muted">
          Posted by ${post.author ? post.author.username : 'Anonymous'} 
          on ${new Date(post.timestamp).toLocaleString()}
        </small>
      </div>
    `;
    
    // Add to the top of the container
    postsContainer.insertBefore(postElement, postsContainer.firstChild);
  }
});
