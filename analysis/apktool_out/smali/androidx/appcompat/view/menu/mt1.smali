.class public final Landroidx/appcompat/view/menu/mt1;
.super Landroidx/appcompat/view/menu/y7;
.source "SourceFile"


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/os/Looper;Landroidx/appcompat/view/menu/y7$a;Landroidx/appcompat/view/menu/y7$b;)V
    .locals 7

    const/16 v3, 0x5d

    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v4, p3

    move-object v5, p4

    invoke-direct/range {v0 .. v6}, Landroidx/appcompat/view/menu/y7;-><init>(Landroid/content/Context;Landroid/os/Looper;ILandroidx/appcompat/view/menu/y7$a;Landroidx/appcompat/view/menu/y7$b;Ljava/lang/String;)V

    return-void
.end method


# virtual methods
.method public final E()Ljava/lang/String;
    .locals 1

    const-string v0, "com.google.android.gms.measurement.internal.IMeasurementService"

    return-object v0
.end method

.method public final F()Ljava/lang/String;
    .locals 1

    const-string v0, "com.google.android.gms.measurement.START"

    return-object v0
.end method

.method public final e()I
    .locals 1

    const v0, 0xbdfcb8

    return v0
.end method

.method public final synthetic s(Landroid/os/IBinder;)Landroid/os/IInterface;
    .locals 2

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    const-string v0, "com.google.android.gms.measurement.internal.IMeasurementService"

    invoke-interface {p1, v0}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    move-result-object v0

    instance-of v1, v0, Landroidx/appcompat/view/menu/ts1;

    if-eqz v1, :cond_1

    check-cast v0, Landroidx/appcompat/view/menu/ts1;

    return-object v0

    :cond_1
    new-instance v0, Landroidx/appcompat/view/menu/xs1;

    invoke-direct {v0, p1}, Landroidx/appcompat/view/menu/xs1;-><init>(Landroid/os/IBinder;)V

    return-object v0
.end method
