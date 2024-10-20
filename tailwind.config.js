/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  
  theme: {
    extend: {
      fontFamily:{
        playfair: ["Playfair Display","serif"],
      },
      screens: {
        'footerSm': '555px',
        'footerMd': '2236px',
        'sm': '640px',
        'md': '768px',
        'lg': '1024px',
        'xl': '1280px',
        '2xl': '1536px',
      },
      colors: {
        "primary": "#EEEEEE",
        "secondary": "#8EACCD",
        "third": "#222831",
        "fourth": "#393E46"
      },
      container: {
        center:true,
        padding: {
          DEFAULT: "1rem",
          sm: "2rem",
          lg: "4rem",
          xl: "5rem",
          "2xl": "6rem",
        }
      }
      
    },
  },
  plugins: [],

}
