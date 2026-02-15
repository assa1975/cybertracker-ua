document.addEventListener('DOMContentLoaded', function() {
    // Date input placeholders
    var dateFrom = document.querySelector('input[name="date_from"]');
    var dateTo = document.querySelector('input[name="date_to"]');
    if (dateFrom && !dateFrom.value) {
        dateFrom.setAttribute('placeholder', 'Дата від');
    }
    if (dateTo && !dateTo.value) {
        dateTo.setAttribute('placeholder', 'Дата до');
    }
});
