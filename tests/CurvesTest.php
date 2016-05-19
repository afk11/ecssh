<?php

namespace Afk11\EcSSH\Tests;

use Afk11\EcSSH\Curves;
use Mdanter\Ecc\Curves\NamedCurveFp;
use Mdanter\Ecc\Primitives\GeneratorPoint;

class CurvesTest extends AbstractTest
{
    public function testTheAllowedCurves()
    {
        $this->assertEquals([
            'nistp256', 'nistp384', 'nistp521'
        ], Curves::listAll());
    }

    /**
     * @return string[]
     */
    public function getCurveNames()
    {
        $results = [];
        foreach (Curves::listAll() as $curve) {
            $results[] = [$curve];
        }

        return $results;
    }

    /**
     * @dataProvider getCurveNames

     */
    public function testReturnsCurve($name)
    {
        $curve = Curves::curve($name);
        $this->assertInstanceOf('\Mdanter\Ecc\Curves\NamedCurveFp', $curve);
    }

    /**
     * @dataProvider getCurveNames
     */
    public function testReturnsGenerator($name)
    {
        $generator = Curves::generator($name);
        $this->assertInstanceOf('\Mdanter\Ecc\Primitives\GeneratorPoint', $generator);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unknown or unsupported curve
     */
    public function testRejectsInvalidCurve()
    {
        Curves::curve('not-a-curve');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unknown or unsupported generator
     */
    public function testRejectsInvalidGenerator()
    {
        Curves::generator('not-a-curve');
    }

    /**
     * @dataProvider getCurveNames
     */
    public function testLoad($name)
    {
        $load = Curves::load($name);
        $this->assertEquals(2, count($load));

        /**
         * @var NamedCurveFp $curve
         * @var GeneratorPoint $generator
         */
        list ($curve, $generator) = $load;
        $this->assertInstanceOf('\Mdanter\Ecc\Curves\NamedCurveFp', $curve);
        $this->assertInstanceOf('\Mdanter\Ecc\Primitives\GeneratorPoint', $generator);
        $this->assertEquals($curve->getName(), $generator->getCurve()->getName());
    }
}
