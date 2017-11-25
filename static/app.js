'use strict';

var app = angular.module('app', []);

app.controller('feed', ['$scope', 'pollsService', function($scope, pollsService) {
  pollsService.getPolls().then((response) => {
    $scope.feed = response.data;
  });
}]);

app.factory('pollsService', ['$http', function($http){
  function getPolls() {
    return $http.get('/showpoll_ng')
    .then((response) => response);
  }

  return {
    getPolls: getPolls
  };
}]);
