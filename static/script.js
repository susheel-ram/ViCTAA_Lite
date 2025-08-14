// // Function to toggle the visibility of the <ul> elements
// document.querySelectorAll('.toggle-header').forEach(header => {
//     header.addEventListener('click', function() {
//         // Toggle the associated <ul> list
//         const list = this.nextElementSibling; // The <ul> immediately after the <h2>

//         // Toggle visibility
//         if (list.style.display === 'none' || list.style.display === '') {
//             list.style.display = 'block';
//         } else {
//             list.style.display = 'none';
//         }

//         // Toggle the active class on the header for styling
//         this.classList.toggle('active');
//     });
// });


document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll('.toggle-header').forEach(header => {
        const list = header.nextElementSibling;

        // Add or remove collapsed class based on presence of .open
        if (list.classList.contains('open')) {
            header.classList.remove('collapsed');
        } else {
            header.classList.add('collapsed');
        }

        header.addEventListener('click', function () {
            list.classList.toggle('open');
            header.classList.toggle('collapsed');
            header.classList.toggle('active');
        });
    });
});

// latest code before changeing on 18.07.2025
// document.addEventListener("DOMContentLoaded", function () {
//     document.querySelectorAll('.toggle-header').forEach(header => {
//         const list = header.nextElementSibling;

//         // Auto-collapse if the list is not visible
//         if (list.style.display !== 'block') {
//             header.classList.add('collapsed');
//         }

//         header.addEventListener('click', function () {
//             if (list.style.display === 'none' || list.style.display === '') {
//                 list.style.display = 'block';
//                 this.classList.remove('collapsed');
//             } else {
//                 list.style.display = 'none';
//                 this.classList.add('collapsed');
//             }
//             this.classList.toggle('active');
//         });
//     });
// });

// document.querySelectorAll('.toggle-header').forEach(header => {
//     header.addEventListener('click', function () {
//         const list = this.nextElementSibling;

//         // Toggle visibility
//         if (list.style.display === 'none' || list.style.display === '') {
//             list.style.display = 'block';
//             this.classList.remove('collapsed');
//         } else {
//             list.style.display = 'none';
//             this.classList.add('collapsed');
//         }

//         // Toggle 'active' class for background color (already there)
//         this.classList.toggle('active');
//     });
// });
