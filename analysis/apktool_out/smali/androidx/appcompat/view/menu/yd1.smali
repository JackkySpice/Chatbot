.class public final Landroidx/appcompat/view/menu/yd1;
.super Landroidx/appcompat/view/menu/r;
.source "SourceFile"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Landroidx/appcompat/view/menu/yd1;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final m:I

.field public final n:Landroid/os/IBinder;

.field public final o:Landroidx/appcompat/view/menu/df;

.field public final p:Z

.field public final q:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/zd1;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/zd1;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/yd1;->CREATOR:Landroid/os/Parcelable$Creator;

    return-void
.end method

.method public constructor <init>(ILandroid/os/IBinder;Landroidx/appcompat/view/menu/df;ZZ)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/r;-><init>()V

    iput p1, p0, Landroidx/appcompat/view/menu/yd1;->m:I

    iput-object p2, p0, Landroidx/appcompat/view/menu/yd1;->n:Landroid/os/IBinder;

    iput-object p3, p0, Landroidx/appcompat/view/menu/yd1;->o:Landroidx/appcompat/view/menu/df;

    iput-boolean p4, p0, Landroidx/appcompat/view/menu/yd1;->p:Z

    iput-boolean p5, p0, Landroidx/appcompat/view/menu/yd1;->q:Z

    return-void
.end method


# virtual methods
.method public final d()Landroidx/appcompat/view/menu/df;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/yd1;->o:Landroidx/appcompat/view/menu/df;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return v0

    :cond_0
    const/4 v1, 0x1

    if-ne p0, p1, :cond_1

    return v1

    :cond_1
    instance-of v2, p1, Landroidx/appcompat/view/menu/yd1;

    if-nez v2, :cond_2

    return v0

    :cond_2
    check-cast p1, Landroidx/appcompat/view/menu/yd1;

    iget-object v2, p0, Landroidx/appcompat/view/menu/yd1;->o:Landroidx/appcompat/view/menu/df;

    iget-object v3, p1, Landroidx/appcompat/view/menu/yd1;->o:Landroidx/appcompat/view/menu/df;

    invoke-virtual {v2, v3}, Landroidx/appcompat/view/menu/df;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_3

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/yd1;->f()Landroidx/appcompat/view/menu/oz;

    move-result-object v2

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/yd1;->f()Landroidx/appcompat/view/menu/oz;

    move-result-object p1

    invoke-static {v2, p1}, Landroidx/appcompat/view/menu/sf0;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_3

    return v1

    :cond_3
    return v0
.end method

.method public final f()Landroidx/appcompat/view/menu/oz;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/yd1;->n:Landroid/os/IBinder;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    invoke-static {v0}, Landroidx/appcompat/view/menu/oz$a;->asInterface(Landroid/os/IBinder;)Landroidx/appcompat/view/menu/oz;

    move-result-object v0

    return-object v0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 4

    invoke-static {p1}, Landroidx/appcompat/view/menu/fr0;->a(Landroid/os/Parcel;)I

    move-result v0

    const/4 v1, 0x1

    iget v2, p0, Landroidx/appcompat/view/menu/yd1;->m:I

    invoke-static {p1, v1, v2}, Landroidx/appcompat/view/menu/fr0;->i(Landroid/os/Parcel;II)V

    iget-object v1, p0, Landroidx/appcompat/view/menu/yd1;->n:Landroid/os/IBinder;

    const/4 v2, 0x2

    const/4 v3, 0x0

    invoke-static {p1, v2, v1, v3}, Landroidx/appcompat/view/menu/fr0;->h(Landroid/os/Parcel;ILandroid/os/IBinder;Z)V

    const/4 v1, 0x3

    iget-object v2, p0, Landroidx/appcompat/view/menu/yd1;->o:Landroidx/appcompat/view/menu/df;

    invoke-static {p1, v1, v2, p2, v3}, Landroidx/appcompat/view/menu/fr0;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;IZ)V

    const/4 p2, 0x4

    iget-boolean v1, p0, Landroidx/appcompat/view/menu/yd1;->p:Z

    invoke-static {p1, p2, v1}, Landroidx/appcompat/view/menu/fr0;->c(Landroid/os/Parcel;IZ)V

    const/4 p2, 0x5

    iget-boolean v1, p0, Landroidx/appcompat/view/menu/yd1;->q:Z

    invoke-static {p1, p2, v1}, Landroidx/appcompat/view/menu/fr0;->c(Landroid/os/Parcel;IZ)V

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/fr0;->b(Landroid/os/Parcel;I)V

    return-void
.end method
