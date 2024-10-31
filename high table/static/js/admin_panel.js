function performAction(action, userId = null) {
    let payload = { action: action };

    if (userId) {
        payload.user_id = userId;
    } else if (action === "add") {
        // Get data from input fields
        payload.username = document.getElementById("username").value;
        payload.password = document.getElementById("password").value;
        payload.first_name = document.getElementById("first_name").value;
        payload.last_name = document.getElementById("last_name").value;
        payload.email = document.getElementById("email").value;
        payload.phone = document.getElementById("phone").value;
        payload.institution = document.getElementById("institution").value;
        payload.role = document.getElementById("role").value;

        // Validation
        if (!payload.username || !payload.password || !payload.first_name || !payload.last_name || !payload.email || !payload.phone || !payload.institution || !payload.role) {
            alert("Please fill in all fields.");
            return;
        }
    } else if (action === "delete" && userId) {
        if (!confirm("Are you sure you want to delete this user?")) {
            return; // Exit if canceled
        }
    }

    fetch("/admin/user_action", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === "success") {
            alert(data.message);
            location.reload();  // Optionally reload to update the user list
        } else {
            alert("Error: " + data.message);
        }
    })
    .catch(error => console.error("Error:", error));
}
