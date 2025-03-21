const path = require('path');
const nodeExternals = require('webpack-node-externals');

module.exports = {
  mode: 'production', // or 'development'
  entry: './app.js', 
  target: 'node',  
  externals: [nodeExternals()],  
  output: {
    path: path.resolve(__dirname, 'dist'),  
    filename: 'srssjt.js',  
  },
  module: {
    rules: [
      {
        test: /\.js$/, 
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env'],
          },
        },
      },
    ],
  },
};
