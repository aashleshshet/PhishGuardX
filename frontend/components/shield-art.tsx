export function ShieldArt() {
  return (
    <div className="shield-scene" aria-hidden="true">
      <div className="shield-orbit orbit-one" />
      <div className="shield-orbit orbit-two" />
      <div className="shield-floor" />
      <svg className="shield-art" viewBox="0 0 300 330" fill="none">
        <defs>
          <linearGradient
            id="glassEdge"
            x1="50"
            y1="40"
            x2="240"
            y2="300"
            gradientUnits="userSpaceOnUse"
          >
            <stop stopColor="#fff" />
            <stop offset=".28" stopColor="#c5eaff" />
            <stop offset=".58" stopColor="#6b9fef" />
            <stop offset="1" stopColor="#fafcff" />
          </linearGradient>
          <linearGradient
            id="glassFace"
            x1="60"
            y1="45"
            x2="250"
            y2="280"
            gradientUnits="userSpaceOnUse"
          >
            <stop stopColor="#f9fdff" stopOpacity=".95" />
            <stop offset=".35" stopColor="#d9edff" stopOpacity=".72" />
            <stop offset=".66" stopColor="#a5cdff" stopOpacity=".52" />
            <stop offset="1" stopColor="#daeaff" stopOpacity=".85" />
          </linearGradient>
          <linearGradient
            id="innerShield"
            x1="85"
            y1="90"
            x2="215"
            y2="260"
            gradientUnits="userSpaceOnUse"
          >
            <stop stopColor="#71b0f6" stopOpacity=".08" />
            <stop offset="1" stopColor="#357ddd" stopOpacity=".28" />
          </linearGradient>
          <linearGradient
            id="check"
            x1="106"
            y1="145"
            x2="200"
            y2="200"
            gradientUnits="userSpaceOnUse"
          >
            <stop stopColor="#61a4f3" />
            <stop offset="1" stopColor="#2663d4" />
          </linearGradient>
          <filter
            id="drop"
            x="0"
            y="0"
            width="300"
            height="350"
            filterUnits="userSpaceOnUse"
          >
            <feDropShadow
              dx="-3"
              dy="19"
              stdDeviation="12"
              floodColor="#376fc3"
              floodOpacity=".19"
            />
          </filter>
        </defs>
        <g filter="url(#drop)">
          <path
            d="m150 27 104 45v84c0 75-62 116-104 137C108 272 46 231 46 156V72L150 27Z"
            fill="url(#glassEdge)"
          />
          <path
            d="m148 31 100 43v81c0 72-59 111-100 133C107 266 49 227 49 155V74l99-43Z"
            fill="url(#glassFace)"
            stroke="white"
            strokeWidth="1.5"
          />
          <path
            d="m148 63 73 31v61c0 53-41 85-73 104-32-19-73-51-73-104V94l73-31Z"
            fill="url(#innerShield)"
            stroke="#f7fcff"
            strokeWidth="1.5"
          />
          <path
            d="m111 158 25 26 50-54"
            stroke="#fff"
            strokeOpacity=".7"
            strokeWidth="15"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="m111 157 25 26 50-54"
            stroke="url(#check)"
            strokeWidth="11"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="m54 78 94-40 91 39"
            stroke="white"
            strokeOpacity=".85"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </g>
      </svg>
      <span className="art-spark spark-one" />
      <span className="art-spark spark-two" />
      <span className="art-spark spark-three" />
      <div className="floating-label">
        <span className="status-dot" /> A little clarity. A safer click.
      </div>
    </div>
  );
}
