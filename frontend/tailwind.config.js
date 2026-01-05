/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'csf-govern': '#8B5CF6',
        'csf-identify': '#3B82F6',
        'csf-protect': '#10B981',
        'csf-detect': '#F59E0B',
        'csf-respond': '#EF4444',
        'csf-recover': '#6366F1',
      },
    },
  },
  plugins: [],
}
