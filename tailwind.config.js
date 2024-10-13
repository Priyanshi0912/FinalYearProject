/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./wcd/website/templates/*.{html,js}"],
  theme: {
    extend: {},
  },
  plugins: [],
}

module.exports = {

  plugins: [
      require('flowbite/plugin')({
        charts: true,
      }),
  ],


}
