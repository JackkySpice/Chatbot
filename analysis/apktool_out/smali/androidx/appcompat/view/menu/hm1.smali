.class public final Landroidx/appcompat/view/menu/hm1;
.super Landroidx/appcompat/view/menu/nj1;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/dm1;


# direct methods
.method public constructor <init>(Landroid/os/IBinder;)V
    .locals 1

    const-string v0, "com.google.android.gms.measurement.api.internal.IBundleReceiver"

    invoke-direct {p0, p1, v0}, Landroidx/appcompat/view/menu/nj1;-><init>(Landroid/os/IBinder;Ljava/lang/String;)V

    return-void
.end method


# virtual methods
.method public final f(Landroid/os/Bundle;)V
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/nj1;->h()Landroid/os/Parcel;

    move-result-object v0

    invoke-static {v0, p1}, Landroidx/appcompat/view/menu/rj1;->d(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    const/4 p1, 0x1

    invoke-virtual {p0, p1, v0}, Landroidx/appcompat/view/menu/nj1;->k(ILandroid/os/Parcel;)V

    return-void
.end method
