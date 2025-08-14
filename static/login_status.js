// $(document).ready(function () {
//     $.getJSON("/get-login-data", function (data) {
//         if (!data || !data.status_counts || data.status_counts.length === 0) {
//             console.error("No data received or invalid API response");
//             return;
//         }

//         let labels = [];
//         let counts = [];
//         let userDetails = {
//             'logged_in': data.logged_in_users || [],
//             'logged_out': data.logged_out_users || []
//         };

//         data.status_counts.forEach(status => {
//             labels.push(status.login_status);
//             counts.push(status.count);
//         });

//         let ctx = document.getElementById('loginChart');
//         if (!ctx) {
//             console.error("Canvas element not found");
//             return;
//         }

//         // **Fix: Ensure previous chart instance is properly destroyed**
//         if (window.loginChart && typeof window.loginChart.destroy === "function") {
//             window.loginChart.destroy();
//         }

//         // **Create a new pie chart**
//         window.loginChart = new Chart(ctx.getContext('2d'), {
//             type: 'pie',
//             data: {
//                 labels: labels,
//                 datasets: [{
//                     label: 'User Status',
//                     data: counts,
//                     backgroundColor: ['red', 'green']
//                 }]
//             },
//             options: {
//                 onClick: function (event, elements) {
//                     if (elements.length > 0) {
//                         let clickedIndex = elements[0].index;
//                         let selectedStatus = labels[clickedIndex].toLowerCase().replace(" ", "_");
//                         showUserDetails(userDetails[selectedStatus], selectedStatus);
//                     }
//                 }
//             }
            
//         });
//     }).fail(function (jqxhr, textStatus, error) {
//         console.error("Error fetching data:", textStatus, error);
//     });

//     // **Add event listener for closing the pop-up**
//     let closeButton = document.getElementById("closeUserPopup");
//     let popup = document.getElementById("userPopup");

//     if (closeButton && popup) {
//         closeButton.addEventListener("click", function () {
//             popup.style.display = "none";
//             console.log("User popup closed"); // Debugging log
//         });
//     } else {
//         console.error("Close button or popup not found");
//     }
// });

// function showUserDetails(users, statusType) {
//     let userList = document.getElementById('userList');
//     let popup = document.getElementById('userPopup');
//     let overlay = document.getElementById('popupOverlay');

//     userList.innerHTML = users.length === 0
//         ? '<li>No users found</li>'
//         : users.map(user => `<li>ID: ${user.id}, Username: ${user.username}</li>`).join('');

//     // If it's "logged_out", apply scroll effect
//     if (statusType === "logged_out") {
//         userList.style.maxHeight = "200px"; // Ensure scroll for many users
//         userList.style.overflowY = "auto";  // Enable vertical scroll
//     } else {
//         userList.style.maxHeight = "none";  // Remove scroll for logged in users
//         userList.style.overflowY = "visible";
//     }

//     popup.style.display = 'block';
//     overlay.style.display = 'block';  // Show overlay
// }

// // Close popup logic
// document.getElementById("closeUserPopup").addEventListener("click", function () {
//     document.getElementById("userPopup").style.display = 'none';
//     document.getElementById("popupOverlay").style.display = 'none';  // Hide overlay
// });

$(document).ready(function () {
    $.getJSON("/get-login-data", function (data) {
        if (!data || !data.status_counts || data.status_counts.length === 0) {
            console.error("No data received or invalid API response");
            return;
        }

        let labels = [];
        let counts = [];
        let userDetails = {
            'logged_in': data.logged_in_users || [],
            'logged_out': data.logged_out_users || []
        };

        data.status_counts.forEach(status => {
            labels.push(status.login_status);
            counts.push(status.count);
        });

        let ctx = document.getElementById('loginChart');
        if (!ctx) {
            console.error("Canvas element not found");
            return;
        }

        // **Fix: Ensure previous chart instance is properly destroyed**
        if (window.loginChart && typeof window.loginChart.destroy === "function") {
            window.loginChart.destroy();
        }

        // **Create a new pie chart**
        window.loginChart = new Chart(ctx.getContext('2d'), {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    label: 'User Status',
                    data: counts,
                    backgroundColor: ['green', 'red']
                }]
            },
            options: {
                onClick: function (event, elements) {
                    if (elements.length > 0) {
                        let clickedIndex = elements[0].index;
                        let selectedStatus = labels[clickedIndex].toLowerCase().replace(" ", "_");
                        showUserDetails(userDetails[selectedStatus], selectedStatus);
                    }
                }
            }
        });
    }).fail(function (jqxhr, textStatus, error) {
        console.error("Error fetching data:", textStatus, error);
    });

    // **Add event listener for closing the pop-up**
    let closeButton = document.getElementById("closeUserPopup");
    let popup = document.getElementById("userPopup");

    if (closeButton && popup) {
        closeButton.addEventListener("click", function () {
            popup.style.display = "none";
            console.log("User popup closed"); // Debugging log
        });
    } else {
        console.error("Close button or popup not found");
    }
});

function showUserDetails(users, statusType) {
    let userList = document.getElementById('userList');
    let popup = document.getElementById('userPopup');
    let overlay = document.getElementById('popupOverlay');

    userList.innerHTML = users.length === 0
        ? '<li>No users found</li>'
        : users.map(user => `<li>ID: ${user.id}, Username: ${user.username}</li>`).join('');

    // If it's "logged_out", apply scroll effect
    if (statusType === "logged_out") {
        userList.style.maxHeight = "200px"; // Ensure scroll for many users
        userList.style.overflowY = "auto";  // Enable vertical scroll
    } else {
        userList.style.maxHeight = "none";  // Remove scroll for logged in users
        userList.style.overflowY = "visible";
    }

    popup.style.display = 'block';
    overlay.style.display = 'block';  // Show overlay
}

// Close popup logic
document.getElementById("closeUserPopup").addEventListener("click", function () {
    document.getElementById("userPopup").style.display = 'none';
    document.getElementById("popupOverlay").style.display = 'none';  // Hide overlay
});
