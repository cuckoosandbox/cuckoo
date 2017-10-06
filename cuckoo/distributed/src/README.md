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
  - gulp.js

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
`params` | `Object` | Object containing the api parameters
`params.include` | `String` | Comma separated list of includable data: `task_completed,task_uncompleted` => `?include=...`
`params.period` | `String` | Comma-separated period representable: `hour,day,week` => `?period=...`
`params.date` | `String` | Date selector: `2017-5-15` => `api/stats/2017-5-15...`
`transform` | `Array/Function` | A transformation function, must always return the formatted response object. External libraries will only receive the formatted data if a transformator is given. Can also be an array of transformation functions.

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

The grid is powered by an external library: `gridstack.js`. This is an extremely
powerfull grid library that allows for dragging and dropping widgets into a grid
of from a single grid to another grid instance. DraggableZ is based on this
framework, by using the DraggableZ constructor, a new grid is created and its
wrapper allows for dynamically adding/removing widgets from that grid.

### DraggableZ API

#### DraggableZ (ctx = (jQuery), widgets = [])

This is the wrapping constructor. A DraggableZ instance is capable of receiving
widgets, as altering and managing widgets. It takes two arguments: `ctx` and `widgets`.

`ctx` is a jQuery selector to the referring element to create a grid on. `widgets`
can be an array of widgets (made with `DraggableZ.fabricate()`, for example) to
auto-initialise widgets onto the grid. An example (bare minimum):

``` javascript

import DraggableZ from './lib/DraggableZ';
const grid = new DraggableZ($("#grid"), []);

```

#### DraggableZ.draw()

Draws the widgets onto the grid, applies listeners etc. This function should
be called when all the widgets have been added into the widgets stack and is ready
for rendering.

#### DraggableZ.initialise(widgets = {});

Called onto construction, creates the Gridstack.js instance, and (if widgets were
pre-passed into the constructor) initializes these widgets.

#### DraggableZ => fabricate(name, options)

This is an external shim of DraggableZ.widget for use outside of the grid context.
This is the function that is being imported into external widget files and exported
the result of that file. it returns a `DraggableZWidget` instance to use in
`DraggableZ.prefabricated()`

#### DraggableZ.prefabricated(widgets)

Takes in an array of widgets and renders them automagically! This is considered
an internal method and should not be used outside of utility.

#### DraggableZ.widget(name = String, options = {})

Creates a widget and injects it into the DraggableZ.widgets array. A widget
consumes a list of different options, so look up this table for some explanatory
features of a widget:

Option | Type | Description
------ | ---- | -----------
`template` | `jQuery` | Refers to the `<template />` the html for the widget lives in (should be in the DOM)
`elementId` | `String` | Is the ID of the element it lives in, will deprecate soon.
`widgetLayout` | `Object` | A list of options to pass to gridstack.js for creating widgets (contains information about size, position etc.)
`loaderText` | `String` | A string to show when the loader is visible
`chartHeight` | `Number` | The height of the chart that is rendered into the widget
`chart` | `Object` | Properties to pass to chart.js for rendering the chart (if applicable)
`api` | `Object`| Properties to pass to StatsApi (internal instance). Refer to the StatsApi guides above for more info.

#### DraggableZ.widgetFabricated(widget = DraggableZWidget)

Adds a pre-fabricated widget into the DraggableZ grid. This is considered an
internal method and should not be used outside of utility.

## The Widgets

A widget should be treated as an application entity that holds its own scope
of data and interactions, configurable in development. Widgets connect a whole
load of services and api's to work for themself internally. This enables unobtrusive
widget behavior, that will load for themselves and won't break other widgets.

Widgets have their own instance of `StatsApi` and `WidgetLoader` and feature their
own event cycles to listen to. Widgets on their time listen to their own instances
as well for deciding which render actions or callbacks to fire, as so they become
their own mechanical decision-making chart-rendering materials that can be altered
easily by user input without caring what the other widgets 'are'.

### DraggableZWidget(name, options)



## The Charts

## The Loader

## The SVG Loader
