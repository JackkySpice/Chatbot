.class public Landroidx/appcompat/view/menu/ef;
.super Landroidx/appcompat/view/menu/r;
.source "SourceFile"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Landroidx/appcompat/view/menu/ef;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final m:Landroidx/appcompat/view/menu/rp0;

.field public final n:Z

.field public final o:Z

.field public final p:[I

.field public final q:I

.field public final r:[I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/x42;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/x42;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/ef;->CREATOR:Landroid/os/Parcelable$Creator;

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/rp0;ZZ[II[I)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/r;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ef;->m:Landroidx/appcompat/view/menu/rp0;

    iput-boolean p2, p0, Landroidx/appcompat/view/menu/ef;->n:Z

    iput-boolean p3, p0, Landroidx/appcompat/view/menu/ef;->o:Z

    iput-object p4, p0, Landroidx/appcompat/view/menu/ef;->p:[I

    iput p5, p0, Landroidx/appcompat/view/menu/ef;->q:I

    iput-object p6, p0, Landroidx/appcompat/view/menu/ef;->r:[I

    return-void
.end method


# virtual methods
.method public d()I
    .locals 1

    iget v0, p0, Landroidx/appcompat/view/menu/ef;->q:I

    return v0
.end method

.method public f()[I
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ef;->p:[I

    return-object v0
.end method

.method public i()[I
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ef;->r:[I

    return-object v0
.end method

.method public k()Z
    .locals 1

    iget-boolean v0, p0, Landroidx/appcompat/view/menu/ef;->n:Z

    return v0
.end method

.method public n()Z
    .locals 1

    iget-boolean v0, p0, Landroidx/appcompat/view/menu/ef;->o:Z

    return v0
.end method

.method public final p()Landroidx/appcompat/view/menu/rp0;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ef;->m:Landroidx/appcompat/view/menu/rp0;

    return-object v0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 4

    invoke-static {p1}, Landroidx/appcompat/view/menu/fr0;->a(Landroid/os/Parcel;)I

    move-result v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/ef;->m:Landroidx/appcompat/view/menu/rp0;

    const/4 v2, 0x1

    const/4 v3, 0x0

    invoke-static {p1, v2, v1, p2, v3}, Landroidx/appcompat/view/menu/fr0;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;IZ)V

    const/4 p2, 0x2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ef;->k()Z

    move-result v1

    invoke-static {p1, p2, v1}, Landroidx/appcompat/view/menu/fr0;->c(Landroid/os/Parcel;IZ)V

    const/4 p2, 0x3

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ef;->n()Z

    move-result v1

    invoke-static {p1, p2, v1}, Landroidx/appcompat/view/menu/fr0;->c(Landroid/os/Parcel;IZ)V

    const/4 p2, 0x4

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ef;->f()[I

    move-result-object v1

    invoke-static {p1, p2, v1, v3}, Landroidx/appcompat/view/menu/fr0;->j(Landroid/os/Parcel;I[IZ)V

    const/4 p2, 0x5

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ef;->d()I

    move-result v1

    invoke-static {p1, p2, v1}, Landroidx/appcompat/view/menu/fr0;->i(Landroid/os/Parcel;II)V

    const/4 p2, 0x6

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ef;->i()[I

    move-result-object v1

    invoke-static {p1, p2, v1, v3}, Landroidx/appcompat/view/menu/fr0;->j(Landroid/os/Parcel;I[IZ)V

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/fr0;->b(Landroid/os/Parcel;I)V

    return-void
.end method
