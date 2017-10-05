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

**Install:**
  - node.js (with npm)
  - gulp

**Then:**
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
    // sets the ?period parameter
    .period('day')
    // sets the ?include parameter
    .include('task_completed,task_uncompleted')
    // sets the /date endpoint
    .date('2017-1-1')
    // makes the call and returns a plain ol' promise for handling the fetch
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
  let onRequest = ()         => processRequest(request);
  let onError   = (err)      => processError(err);

  // sets parameters
  api
    .period('day')
    .include('task_completed')
    .date('2017-1-1');

  // attach event handlers to the api instance
  api.on('receive', response => onReceive(response));
  api.on('request', params   => onRequest(params));
  api.on('error', (err)      => onError(err));

  // do the request with fetch
  api.fetch();
```

Above examples offer a great way of handling parameters configured
by the UI itself (from a dropdown example). This allows for easily making
calls and updating the UI where possible with not-so-much configuration,
keeping the other libraries primarily focussed on doing their thing as
abstract as possible.

### StatsApi API

#### StatsApi(options = {})

The main constructor, when you instantiate a new instance, you call this
constructor like `new StatsApi({...})`.

**Accepted options:**\

option | type | value
------ | ---- | -----
`params` | Object | Object containing the api parameters
`params.include` | String | Comma separated list of includable data: `task_completed,task_uncompleted` => `?include=...`
`params.period` | String | Comma-separated period representable: `hour,day,week` => `?period=...`
`params.date` | String | Date selector: `2017-5-15` => `api/stats/2017-5-15...`
`transform` | Array/Function | A transformation function, must always return the formatted response object. External libraries will only receive the formatted data if a transformator is given. Can also be an array of transformation functions.

**Accepted include parameters**\
- `task_completed` - list of completed tasks since `date` in `period`
- `task_uncompleted` - list of uncompleted tasks since `date` in `period`
- `vm_running` - all running vm's
- `disk_usage` - cuckoo disk usage
- `cpu_usage` - cuckoo cpu usage
- `memory_usage` - cuckoo memory usage
- `amount_prio_queued` - amount of prioritized task queues
- `active_processes` - current active processes

**Accepted period parameters**\
_note: These are only for the `task_completed` and `task_uncompleted` calls_
- `hour` - returns the last hour data in `minutes`
- `day` - returns the last day date in `hours`
- `week` - returns the last week date in `days`

**Timestamp formatting**\
From the service backend docs: _"datetime format is always: YYYY-MM-DD HH:MM:SS"_\
for .date(), only use a day-date, no time support.

#### StatsApi.buildURL() [=> String url]

This method constructs the url from the given parameters. it will render something like:\
`http://localhost:9003/api/stats/2017-5-15?include=task_completed&period=hour`\
depending on the `api.params` configuration.

#### StatsApi.date([String date]) [=> api]

Chainable method to configure `api.params.date`.

#### StatsApi.dispatchEvent([String event], [Object data]) [=> api]

Dispatches (triggers) an event cycle. A data object can be passed as well to the
event handler.

#### StatsApi.fetch() [=> Promise]

This chainable method will call `buildURL()` and requests to it. It will resolve
like a promise (.then(...).catch(...)) to deliver its (transformed) response to
the front-end libraries that depend on it.

#### StatsApi.include([String include]) [=> api]

Chainable method to configure `api.params.include`.

#### StatsApi.on([String event], [Function callback])

Adds callbacks to the event cycle stack. These event listeners are executed
when the internal `api.dispatchEvent(evt)` fires. Supported events:

Event | Description
----- | -----------
`request` | Cycles when a request did start
`received` | Cycles when a request did finish OK. Sends the response to the callback
`error` | Cycles when a request was erroreous.

#### StatsApi.period([String period]) [=> api]

Chainable method to configure `api.params.period`.

#### StatsApi.transform([Function transformation]) [=> api]

Chainable method to add transformations to `api.transforms`.

## The Grid

## The Widgets
