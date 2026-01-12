.class public Landroidx/appcompat/view/menu/v11;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final a:Landroidx/appcompat/view/menu/n4;

.field public final b:Landroid/util/SparseArray;

.field public final c:Landroidx/appcompat/view/menu/ka0;

.field public final d:Landroidx/appcompat/view/menu/n4;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Landroidx/appcompat/view/menu/n4;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/n4;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/v11;->a:Landroidx/appcompat/view/menu/n4;

    new-instance v0, Landroid/util/SparseArray;

    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/v11;->b:Landroid/util/SparseArray;

    new-instance v0, Landroidx/appcompat/view/menu/ka0;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/ka0;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/v11;->c:Landroidx/appcompat/view/menu/ka0;

    new-instance v0, Landroidx/appcompat/view/menu/n4;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/n4;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/v11;->d:Landroidx/appcompat/view/menu/n4;

    return-void
.end method
