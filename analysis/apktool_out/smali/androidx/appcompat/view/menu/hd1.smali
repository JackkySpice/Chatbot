.class public final Landroidx/appcompat/view/menu/hd1;
.super Landroidx/appcompat/view/menu/r;
.source "SourceFile"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Landroidx/appcompat/view/menu/hd1;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final m:I

.field public final n:Landroidx/appcompat/view/menu/df;

.field public final o:Landroidx/appcompat/view/menu/yd1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/jd1;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/jd1;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/hd1;->CREATOR:Landroid/os/Parcelable$Creator;

    return-void
.end method

.method public constructor <init>(ILandroidx/appcompat/view/menu/df;Landroidx/appcompat/view/menu/yd1;)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/r;-><init>()V

    iput p1, p0, Landroidx/appcompat/view/menu/hd1;->m:I

    iput-object p2, p0, Landroidx/appcompat/view/menu/hd1;->n:Landroidx/appcompat/view/menu/df;

    iput-object p3, p0, Landroidx/appcompat/view/menu/hd1;->o:Landroidx/appcompat/view/menu/yd1;

    return-void
.end method


# virtual methods
.method public final d()Landroidx/appcompat/view/menu/df;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/hd1;->n:Landroidx/appcompat/view/menu/df;

    return-object v0
.end method

.method public final f()Landroidx/appcompat/view/menu/yd1;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/hd1;->o:Landroidx/appcompat/view/menu/yd1;

    return-object v0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 4

    invoke-static {p1}, Landroidx/appcompat/view/menu/fr0;->a(Landroid/os/Parcel;)I

    move-result v0

    const/4 v1, 0x1

    iget v2, p0, Landroidx/appcompat/view/menu/hd1;->m:I

    invoke-static {p1, v1, v2}, Landroidx/appcompat/view/menu/fr0;->i(Landroid/os/Parcel;II)V

    iget-object v1, p0, Landroidx/appcompat/view/menu/hd1;->n:Landroidx/appcompat/view/menu/df;

    const/4 v2, 0x2

    const/4 v3, 0x0

    invoke-static {p1, v2, v1, p2, v3}, Landroidx/appcompat/view/menu/fr0;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;IZ)V

    const/4 v1, 0x3

    iget-object v2, p0, Landroidx/appcompat/view/menu/hd1;->o:Landroidx/appcompat/view/menu/yd1;

    invoke-static {p1, v1, v2, p2, v3}, Landroidx/appcompat/view/menu/fr0;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;IZ)V

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/fr0;->b(Landroid/os/Parcel;I)V

    return-void
.end method
