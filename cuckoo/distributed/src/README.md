# DraggableZ
A custom dashboard framework for Cuckoo Distributed.

features:
  - Implemented modularity patterns for rapid development
  - Independant asynchronous widgets
  - Draggable widgets (powered by gridstack.js)
  - Chainable/Eventable API service
  - SVG-first graphical support

## Getting started
Before one can start developing awe-some dashboards and widgets for the
distributed data, one must set up a few things:

*Install:*
  - node.js (with npm)
  - gulp

*Then:*
  - from the distributed folder, cd into `src` and run `$ npm install`,
    this will install all the node.js and frontend packages needed
  - run `gulp lib` to generate a version of the client frameworks in advance
  - run `npm start` to start watching the development `scripts` and `scss`
    folders.
  - Also make sure to start `cuckoo distributed server` on the designated port
    to view the interface and start the API service

## Development
Developing works pretty straightforwards in the sense that everything is as
modularized as possible. If you're working on widgets, you're working in
`/src/scripts/widgets` and their accompanied templates in `/templates`. Very
minimal setup is required to get the widget placed in the dashboard. More on
widgets and their properties later on.

## StatsAPI
`StatsAPI({options})` is a utility wrapper around the Cuckoo distributed back-end
service that is chainable and eventable. This makes it amazingly easy to request
data from the service. A request is being passed along as a set of promises, so
creating callbacks is a breeze. An example:

```javascript
  // import StatsAPI from the library
  import StatsAPI from './lib/StatsAPI';

  // transformation function
  function transformation(response, params) {
    response.iAmTransformed = true;
    return response;
  }

  // set up api with the right directives
  const api = new StatsAPI({
    params: {
      include: 'task_completed,task_uncompleted',
      period: 'hour,day,week',
      date: '2017-5-15'
    },
    transform: transformation
  });

  /*
    Retrieving data #1: Resolve like a promise
    - configure all the parameters chainable one after another
      untill .fetch() is called - that will wrap down all the
      properties to a url and request that, then resolves like
      a Promise.
   */
  api
    .period('day')
    .date('2017-1-1')
    .include('task_completed,task_uncompleted')
    .fetch().then(response => {
      console.log(response);
    }).catch(err => {
      console.log(err);
    });

  /*
    Retrieving data #2: Listen for changes
    - This is an event-approach
   */

  let onReceive = (response) => processResponse(response);
  let onRequest = () => processRequest(request);
  let onError   = (err) = => processError(err);

  api.period('day').include('task_completed').date('2017-1-1');

  api.on('receive', response => onReceive(response));
  api.on('request', params => onRequest(params));
  api.on('error', (err) => onError(err));

  // this will actually do the request, firing the above
  // events on there occurence. so each time you would do
  // api.fetch(), above event handlers will fire.
  api.fetch();
```

Above examples offer a great way of handling parameters configured
by the UI itself (from a dropdown example). This allows for easily making
calls and updating the UI where possible with not-so-much configuration,
keeping the other libraries primarily focussed on doing their thing as
abstract as possible.

## The Grid

## The Widgets
